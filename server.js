require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'todo-jwt-secret-change-in-prod';
const RP_NAME   = 'My Tasks';
const RP_ID     = process.env.RP_ID     || 'localhost';
const RP_ORIGIN = process.env.RP_ORIGIN || 'http://localhost:3001';

const sb = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── Auth middleware ───────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}
function makeToken(u) { return jwt.sign({ id: u.id, phone: u.phone }, JWT_SECRET, { expiresIn: '30d' }); }
function pub(u) { return { id: u.id, phone: u.phone }; }

// ── DB helpers ─────────────────────────────────────────────
async function getUser(filter) {
  const { data } = await sb.from('users').select('*').match(filter).maybeSingle();
  return data;
}
async function getOrCreateUser(phone) {
  let u = await getUser({ phone });
  if (!u) {
    const { data } = await sb.from('users').insert({
      phone, webauthn_credentials: [], streak_dates: [], custom_categories: [],
    }).select().single();
    u = data;
  }
  return u;
}
async function setChallenge(key, challenge) {
  await sb.from('auth_challenges').upsert({ key, challenge, expiry: new Date(Date.now() + 5 * 60_000).toISOString() });
}
async function getChallenge(key) {
  const { data } = await sb.from('auth_challenges').select('*').eq('key', key).maybeSingle();
  if (!data || new Date(data.expiry) < new Date()) return null;
  return data.challenge;
}
async function deleteChallenge(key) { await sb.from('auth_challenges').delete().eq('key', key); }
async function setOTP(phone, code) {
  await sb.from('auth_otps').upsert({ phone, code, expiry: new Date(Date.now() + 10 * 60_000).toISOString() });
}
async function getOTP(phone) {
  const { data } = await sb.from('auth_otps').select('*').eq('phone', phone).maybeSingle();
  if (!data || new Date(data.expiry) < new Date()) return null;
  return data;
}
async function deleteOTP(phone) { await sb.from('auth_otps').delete().eq('phone', phone); }

// ── Phone check ───────────────────────────────────────────
app.post('/api/auth/phone-check', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Phone required' });
  const user = await getUser({ phone });
  res.json({ exists: !!user, hasWebAuthn: !!(user?.webauthn_credentials?.length) });
});

// ── WebAuthn: registration ────────────────────────────────
app.post('/api/auth/webauthn/register-options', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone required' });
    const user = await getOrCreateUser(phone);
    const options = await generateRegistrationOptions({
      rpName: RP_NAME, rpID: RP_ID,
      userID: Buffer.from(user.id), userName: phone, userDisplayName: phone,
      attestationType: 'none',
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'required' },
      excludeCredentials: (user.webauthn_credentials || []).map(c => ({
        id: Buffer.from(c.credentialID, 'base64url'), type: 'public-key',
      })),
    });
    await setChallenge(`reg:${phone}`, options.challenge);
    res.json(options);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/webauthn/register', async (req, res) => {
  try {
    const { phone, credential } = req.body;
    const challenge = await getChallenge(`reg:${phone}`);
    if (!challenge) return res.status(400).json({ error: 'Challenge expired, try again' });
    const verification = await verifyRegistrationResponse({
      response: credential, expectedChallenge: challenge,
      expectedOrigin: RP_ORIGIN, expectedRPID: RP_ID, requireUserVerification: true,
    });
    if (!verification.verified) return res.status(400).json({ error: 'Verification failed' });
    const { registrationInfo } = verification;
    const user = await getUser({ phone });
    if (!user) return res.status(404).json({ error: 'User not found' });
    const creds = [...(user.webauthn_credentials || []), {
      credentialID: Buffer.from(registrationInfo.credentialID).toString('base64url'),
      credentialPublicKey: Buffer.from(registrationInfo.credentialPublicKey).toString('base64'),
      counter: registrationInfo.counter,
      transports: credential.response?.transports || [],
    }];
    await sb.from('users').update({ webauthn_credentials: creds }).eq('id', user.id);
    await deleteChallenge(`reg:${phone}`);
    res.json({ token: makeToken(user), user: pub(user) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── WebAuthn: authentication ──────────────────────────────
app.post('/api/auth/webauthn/login-options', async (req, res) => {
  try {
    const { phone } = req.body;
    const user = await getUser({ phone });
    if (!user?.webauthn_credentials?.length) return res.status(404).json({ error: 'No passkey registered' });
    const options = await generateAuthenticationOptions({
      rpID: RP_ID, userVerification: 'required',
      allowCredentials: user.webauthn_credentials.map(c => ({
        id: Buffer.from(c.credentialID, 'base64url'), type: 'public-key', transports: c.transports || [],
      })),
    });
    await setChallenge(`auth:${phone}`, options.challenge);
    res.json(options);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/webauthn/login', async (req, res) => {
  try {
    const { phone, credential } = req.body;
    const challenge = await getChallenge(`auth:${phone}`);
    if (!challenge) return res.status(400).json({ error: 'Challenge expired, try again' });
    const user = await getUser({ phone });
    if (!user) return res.status(404).json({ error: 'User not found' });
    const cred = (user.webauthn_credentials || []).find(c => c.credentialID === credential.id);
    if (!cred) return res.status(400).json({ error: 'Credential not found' });
    const verification = await verifyAuthenticationResponse({
      response: credential, expectedChallenge: challenge,
      expectedOrigin: RP_ORIGIN, expectedRPID: RP_ID, requireUserVerification: true,
      authenticator: {
        credentialID: Buffer.from(cred.credentialID, 'base64url'),
        credentialPublicKey: Buffer.from(cred.credentialPublicKey, 'base64'),
        counter: cred.counter, transports: cred.transports,
      },
    });
    if (!verification.verified) return res.status(400).json({ error: 'Verification failed' });
    const updatedCreds = user.webauthn_credentials.map(c =>
      c.credentialID === credential.id ? { ...c, counter: verification.authenticationInfo.newCounter } : c
    );
    await sb.from('users').update({ webauthn_credentials: updatedCreds }).eq('id', user.id);
    await deleteChallenge(`auth:${phone}`);
    res.json({ token: makeToken(user), user: pub(user) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── OTP ───────────────────────────────────────────────────
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone required' });
    const code = String(Math.floor(100000 + Math.random() * 900000));
    await setOTP(phone, code);
    console.log(`\n  OTP for ${phone}: ${code}\n`);
    // Real SMS: set TWILIO_SID + TWILIO_TOKEN + TWILIO_FROM env vars and uncomment:
    // require('twilio')(process.env.TWILIO_SID, process.env.TWILIO_TOKEN)
    //   .messages.create({ body: `Your My Tasks code: ${code}`, from: process.env.TWILIO_FROM, to: phone });
    res.json({ ok: true, devCode: code });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { phone, code } = req.body;
    const stored = await getOTP(phone);
    if (!stored) return res.status(400).json({ error: 'Code expired' });
    if (stored.code !== String(code).trim()) return res.status(400).json({ error: 'Incorrect code' });
    await deleteOTP(phone);
    const user = await getOrCreateUser(phone);
    res.json({ token: makeToken(user), user: pub(user) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const user = await getUser({ id: req.user.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(pub(user));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Tasks ─────────────────────────────────────────────────
app.get('/api/tasks', auth, async (req, res) => {
  try {
    const { data: tasks } = await sb.from('tasks').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false });
    res.json(tasks || []);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tasks', auth, async (req, res) => {
  try {
    const { title, notes, priority, category, due_date, has_time, recurrence, completed } = req.body;
    if (!title?.trim()) return res.status(400).json({ error: 'Title required' });
    const { data: task } = await sb.from('tasks').insert({
      user_id: req.user.id, title: title.trim(), notes: notes || null,
      priority: priority || 'medium', category: category || 'Personal',
      due_date: due_date || null, has_time: has_time ?? false,
      recurrence: recurrence || null, completed: completed ?? false,
    }).select().single();
    res.status(201).json(task);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/tasks/:id', auth, async (req, res) => {
  try {
    const allowed = ['title','notes','priority','category','due_date','has_time','recurrence','completed'];
    const updates = { updated_at: new Date().toISOString() };
    allowed.forEach(k => { if (k in req.body) updates[k] = req.body[k]; });
    const { data: task } = await sb.from('tasks').update(updates)
      .eq('id', req.params.id).eq('user_id', req.user.id).select().maybeSingle();
    if (!task) return res.status(404).json({ error: 'Task not found' });
    res.json(task);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/tasks/:id', auth, async (req, res) => {
  try {
    const { data } = await sb.from('tasks').delete()
      .eq('id', req.params.id).eq('user_id', req.user.id).select().maybeSingle();
    if (!data) return res.status(404).json({ error: 'Task not found' });
    res.status(204).end();
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/tasks/:id/toggle', auth, async (req, res) => {
  try {
    const { data: task } = await sb.from('tasks').select('*')
      .eq('id', req.params.id).eq('user_id', req.user.id).maybeSingle();
    if (!task) return res.status(404).json({ error: 'Task not found' });
    const newCompleted = !task.completed;
    const { data: updated } = await sb.from('tasks')
      .update({ completed: newCompleted, updated_at: new Date().toISOString() })
      .eq('id', task.id).select().single();
    let spawned = null;
    if (newCompleted && task.recurrence) {
      const base = task.due_date ? new Date(task.due_date) : new Date();
      const next = new Date(base);
      if (task.recurrence === 'daily') next.setDate(next.getDate() + 1);
      else next.setDate(next.getDate() + 7);
      const { data: newTask } = await sb.from('tasks').insert({
        user_id: task.user_id, title: task.title, notes: task.notes,
        priority: task.priority, category: task.category,
        due_date: next.toISOString(), has_time: task.has_time,
        recurrence: task.recurrence, completed: false,
      }).select().single();
      spawned = newTask;
    }
    res.json({ task: updated, spawned });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Categories ────────────────────────────────────────────
const DEFAULT_CATS = [
  { id:'work',     name:'Work',     color:'#4A90E2', isDefault:true },
  { id:'personal', name:'Personal', color:'#E879A0', isDefault:true },
  { id:'shopping', name:'Shopping', color:'#FF7043', isDefault:true },
  { id:'health',   name:'Health',   color:'#26C6DA', isDefault:true },
  { id:'other',    name:'Other',    color:'#9575CD', isDefault:true },
];

app.get('/api/categories', auth, async (req, res) => {
  try {
    const { data: user } = await sb.from('users').select('custom_categories').eq('id', req.user.id).single();
    res.json([...DEFAULT_CATS, ...(user?.custom_categories || [])]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/categories', auth, async (req, res) => {
  try {
    const { name, color } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
    const { data: user } = await sb.from('users').select('custom_categories').eq('id', req.user.id).single();
    const cat = { id: uuidv4(), name: name.trim(), color: color || '#9575CD', isDefault: false, created_at: new Date().toISOString() };
    await sb.from('users').update({ custom_categories: [...(user?.custom_categories || []), cat] }).eq('id', req.user.id);
    res.status(201).json(cat);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/categories/:id', auth, async (req, res) => {
  try {
    const { name, color } = req.body;
    const { data: user } = await sb.from('users').select('custom_categories').eq('id', req.user.id).single();
    const cats = user?.custom_categories || [];
    const idx = cats.findIndex(c => c.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Category not found' });
    if (name) cats[idx].name = name.trim();
    if (color) cats[idx].color = color;
    await sb.from('users').update({ custom_categories: cats }).eq('id', req.user.id);
    res.json(cats[idx]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/categories/:id', auth, async (req, res) => {
  try {
    const { data: user } = await sb.from('users').select('custom_categories').eq('id', req.user.id).single();
    const cats = (user?.custom_categories || []).filter(c => c.id !== req.params.id);
    await sb.from('users').update({ custom_categories: cats }).eq('id', req.user.id);
    res.status(204).end();
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Streak ────────────────────────────────────────────────
app.get('/api/streak', auth, async (req, res) => {
  try {
    const { data: user } = await sb.from('users').select('streak_dates').eq('id', req.user.id).single();
    const dates = user?.streak_dates || [];
    const fmt = d => new Date(d).toISOString().slice(0, 10);
    const today = fmt(new Date());
    let streak = 0; let day = new Date();
    while (dates.includes(fmt(day))) { streak++; day.setDate(day.getDate() - 1); }
    const week = [];
    for (let i = 6; i >= 0; i--) { const d = new Date(); d.setDate(d.getDate() - i); week.push(dates.includes(fmt(d))); }
    res.json({ streak, week, today_recorded: dates.includes(today) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/streak/record', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const { data: user } = await sb.from('users').select('streak_dates').eq('id', req.user.id).single();
    const dates = user?.streak_dates || [];
    if (!dates.includes(today)) {
      await sb.from('users').update({ streak_dates: [...dates, today] }).eq('id', req.user.id);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Apple Calendar ICS feed ───────────────────────────────
function fmtICS(d) { return d.toISOString().replace(/[-:]/g,'').split('.')[0]+'Z'; }
function fmtICSDate(d) { return d.toISOString().slice(0,10).replace(/-/g,''); }
function escICS(s) { return (s||'').replace(/\\/g,'\\\\').replace(/;/g,'\\;').replace(/,/g,'\\,').replace(/\n/g,'\\n'); }
function foldICS(line) {
  if (line.length <= 75) return line;
  let out = line.slice(0,75); let i = 75;
  while (i < line.length) { out += '\r\n ' + line.slice(i, i+74); i += 74; }
  return out;
}

app.get('/api/user/calendar-token', auth, async (req, res) => {
  try {
    const { data: user } = await sb.from('users').select('calendar_token').eq('id', req.user.id).single();
    let tok = user?.calendar_token;
    if (!tok) {
      tok = uuidv4();
      await sb.from('users').update({ calendar_token: tok }).eq('id', req.user.id);
    }
    const origin = process.env.RP_ORIGIN || 'https://todowebsite-six.vercel.app';
    res.json({ url: `${origin}/api/calendar/${tok}`, token: tok });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/calendar/:token', async (req, res) => {
  try {
    const { data: user } = await sb.from('users').select('id').eq('calendar_token', req.params.token).maybeSingle();
    if (!user) return res.status(404).end();
    const { data: tasks } = await sb.from('tasks').select('*').eq('user_id', user.id).not('due_date', 'is', null);
    const now = new Date();
    const lines = [
      'BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//My Tasks//EN',
      'CALSCALE:GREGORIAN','METHOD:PUBLISH',
      'X-WR-CALNAME:My Tasks','X-WR-CALDESC:Tasks from My Tasks',
    ];
    for (const t of (tasks || [])) {
      const s = new Date(t.due_date);
      const e = new Date(s.getTime() + 3600000);
      const prio = t.priority==='high' ? 1 : t.priority==='medium' ? 5 : 9;
      const evLines = [
        'BEGIN:VEVENT',
        `UID:${t.id}@my-tasks`,
        `DTSTAMP:${fmtICS(now)}`,
        t.has_time ? `DTSTART:${fmtICS(s)}` : `DTSTART;VALUE=DATE:${fmtICSDate(s)}`,
        t.has_time ? `DTEND:${fmtICS(e)}` : `DTEND;VALUE=DATE:${fmtICSDate(s)}`,
        foldICS(`SUMMARY:${escICS(t.title)}`),
        t.notes ? foldICS(`DESCRIPTION:${escICS(t.notes)}`) : null,
        `STATUS:${t.completed ? 'COMPLETED' : 'CONFIRMED'}`,
        `PRIORITY:${prio}`,
        'END:VEVENT',
      ].filter(Boolean);
      lines.push(...evLines);
    }
    lines.push('END:VCALENDAR');
    res.setHeader('Content-Type','text/calendar; charset=utf-8');
    res.setHeader('Content-Disposition','inline; filename="my-tasks.ics"');
    res.setHeader('Cache-Control','no-cache, must-revalidate');
    res.send(lines.join('\r\n'));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Public config (non-secret values for the frontend) ───
app.get('/api/config', (req, res) => {
  res.json({ geminiKey: process.env.GEMINI_KEY || '' });
});

// ── Local dev: serve frontend ─────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

if (require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => console.log(`Todo app → http://localhost:${PORT}`));
}

module.exports = app;
