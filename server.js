const express = require('express');
const cors    = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const app  = express();
const PORT = process.env.PORT || 10000;

// ── SECRETS — ENV ONLY, no fallbacks ──────────────────────
const ADMIN_PASS = process.env.ADMIN_PASS;
const ADMIN_KEY  = process.env.ADMIN_KEY;
const APP_SECRET = process.env.APP_SECRET;

if (!ADMIN_PASS || !ADMIN_KEY || !APP_SECRET) {
  console.error('FATAL: ADMIN_PASS, ADMIN_KEY, APP_SECRET set nahi hain!');
  process.exit(1);
}
if (!process.env.FIREBASE_PROJECT_ID) {
  console.error('FATAL: Firebase env vars set nahi hain!');
  process.exit(1);
}

// ── MIDDLEWARE ─────────────────────────────────────────────
app.use(cors({ origin: true }));
app.use(express.json({ limit: '1mb' }));

// Global rate limit — 120 req/min per IP
const _gl = {};
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
  const now = Date.now();
  if (!_gl[ip]) _gl[ip] = [];
  _gl[ip] = _gl[ip].filter(t => now - t < 60000);
  if (_gl[ip].length > 120) return res.status(429).json({ ok: false, msg: 'Too many requests' });
  _gl[ip].push(now);
  next();
});

// APP SECRET check — /admin routes use dual-key auth, skip here
app.use((req, res, next) => {
  if (req.path.startsWith('/admin')) return next();
  if (req.headers['x-app'] !== APP_SECRET) return res.status(403).json({ ok: false, msg: 'Forbidden' });
  next();
});

// Bot filter
app.use((req, res, next) => {
  if (!req.headers['user-agent']) return res.status(403).json({ ok: false, msg: 'Forbidden' });
  next();
});

// ── FIREBASE INIT ──────────────────────────────────────────
initializeApp({
  credential: cert({
    projectId:   process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  })
});
const db = getFirestore();

// Collection shortcuts
const C = {
  users:    () => db.collection('users'),
  rounds:   () => db.collection('rounds'),
  bets:     () => db.collection('bets'),
  settings: () => db.collection('settings'),
  meta:     () => db.collection('meta'),
  blocked:  () => db.collection('blocked'),
  seclog:   () => db.collection('securityLog'),
};

// ── ADMIN AUTH — dual key + brute force protection ─────────
const _adminFails = {};
function auth(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
  if (!_adminFails[ip]) _adminFails[ip] = { n: 0, until: 0 };
  if (Date.now() < _adminFails[ip].until) return false; // still locked
  const pass = req.headers['x-pass'];
  const key  = req.headers['x-key'];
  if (!pass || !key || pass !== ADMIN_PASS || key !== ADMIN_KEY) {
    _adminFails[ip].n++;
    if (_adminFails[ip].n >= 5) _adminFails[ip].until = Date.now() + 15 * 60 * 1000; // lock 15 min
    return false;
  }
  _adminFails[ip] = { n: 0, until: 0 }; // reset on success
  return true;
}

// ── HELPERS ────────────────────────────────────────────────
function uid()  { return Date.now().toString(36) + Math.random().toString(36).substr(2, 5).toUpperCase(); }
function clean(s) { return String(s || '').replace(/[<>{}$]/g, '').trim().slice(0, 500); }
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}
function genCode() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 8; i++) { if (i === 4) s += '-'; s += c[Math.floor(Math.random() * c.length)]; }
  return s;
}

// ── IN-MEMORY RATE LIMITER ─────────────────────────────────
const _rl = {};
function checkRate(key, limit, windowMs) {
  const now = Date.now();
  if (!_rl[key]) _rl[key] = [];
  _rl[key] = _rl[key].filter(t => now - t < windowMs);
  if (_rl[key].length >= limit) return false;
  _rl[key].push(now);
  return true;
}

// ── SETTINGS ───────────────────────────────────────────────
const DEFAULT_SETTINGS = {
  upiId: '', upiName: 'Admin', minBet: 10, maxBet: 5000,
  multiplier: 9, tgLink: 'https://t.me/Winx1010',
  minWithdraw: 300, coinRate: 1
};
async function getSettings() {
  try {
    const s = await C.settings().doc('main').get();
    return s.exists ? { ...DEFAULT_SETTINGS, ...s.data() } : DEFAULT_SETTINGS;
  } catch(e) { return DEFAULT_SETTINGS; }
}

// ── USER HELPERS ───────────────────────────────────────────
async function getUser(code) {
  try {
    const s = await C.users().doc(code.toUpperCase()).get();
    return s.exists ? { ...s.data(), code: s.id } : null;
  } catch(e) { return null; }
}
async function updateUser(code, data) {
  try { await C.users().doc(code.toUpperCase()).set(data, { merge: true }); } catch(e) {}
}

// ── ROUND HELPERS ──────────────────────────────────────────
async function getCurrentRound() {
  try {
    const meta = await C.meta().doc('currentRound').get();
    if (!meta.exists || !meta.data().roundId) return null;
    const r = await C.rounds().doc(meta.data().roundId).get();
    return r.exists ? { ...r.data(), id: r.id } : null;
  } catch(e) { return null; }
}
async function setCurrentRound(roundId) {
  await C.meta().doc('currentRound').set({ roundId: roundId || null });
}

// ── BET HELPERS ────────────────────────────────────────────
async function getBetsByRound(roundId) {
  try {
    const s = await C.bets().where('roundId', '==', roundId).get();
    return s.docs.map(d => ({ ...d.data(), id: d.id }));
  } catch(e) { return []; }
}
async function getUserBetInRound(roundId, userCode) {
  try {
    const s = await C.bets()
      .where('roundId', '==', roundId)
      .where('userCode', '==', userCode)
      .where('status', '!=', 'rejected')
      .limit(1).get();
    return s.empty ? null : { ...s.docs[0].data(), id: s.docs[0].id };
  } catch(e) { return null; }
}
async function utrExists(utr) {
  try {
    const s = await C.bets().where('utr', '==', utr).limit(1).get();
    return !s.empty;
  } catch(e) { return false; }
}

// ── BLOCKED HELPERS ────────────────────────────────────────
async function isDeviceBlocked(deviceId) {
  if (!deviceId) return false;
  try { return (await C.blocked().doc('dev_' + deviceId).get()).exists; } catch(e) { return false; }
}
async function blockDevice(deviceId) {
  await C.blocked().doc('dev_' + deviceId).set({ deviceId, blockedAt: Date.now(), type: 'device' });
}

// ── SECURITY LOG ───────────────────────────────────────────
async function secLog(type, data) {
  try { await C.seclog().add({ type, data, at: Date.now() }); } catch(e) {}
}

// ═══════════════════════════════════════════════════════════
// AUTO-CLOSE BETTING AT 40 MIN
// ═══════════════════════════════════════════════════════════
setInterval(async () => {
  try {
    const round = await getCurrentRound();
    if (!round || round.status !== 'open') return;
    if (Date.now() >= round.startedAt + 40 * 60 * 1000) {
      await C.rounds().doc(round.id).set({ status: 'closed', closedAt: Date.now() }, { merge: true });
      console.log('Auto-closed round:', round.id);
    }
  } catch(e) {}
}, 15000);

// ═══════════════════════════════════════════════════════════
// PUBLIC ROUTES
// ═══════════════════════════════════════════════════════════

app.get('/', (req, res) => res.json({ status: 'NUMBET OK', version: '6.0' }));

// ── LOGIN ──────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { code, deviceId } = req.body;
  const ip = getIP(req);
  if (!code) return res.json({ ok: false, msg: 'Code daalo' });
  const cleanCode = clean(code).toUpperCase();

  // Rate limit: 5 login attempts per min per IP
  if (!checkRate('login:' + ip, 5, 60000)) {
    await secLog('RATE_LIMIT', { ip, code: cleanCode, action: 'login' });
    return res.json({ ok: false, msg: 'Bahut zyada attempts. 1 minute baad try karo.' });
  }

  const [user, settings] = await Promise.all([getUser(cleanCode), getSettings()]);

  if (!user) {
    await secLog('LOGIN_FAIL', { ip, code: cleanCode });
    return res.json({ ok: false, msg: 'Galat code — Telegram se lo: @Winx1010' });
  }
  if (user.banned) {
    await secLog('BANNED_LOGIN', { ip, code: cleanCode });
    return res.json({ ok: false, msg: 'Aapka account block hai. Admin se contact karo.' });
  }
  if (deviceId && await isDeviceBlocked(deviceId)) {
    await secLog('BLOCKED_DEVICE', { ip, code: cleanCode, deviceId });
    return res.json({ ok: false, msg: 'Yeh device block hai.' });
  }

  const updates = { lastLoginAt: Date.now(), lastLoginIP: ip };

  if (!user.deviceId && deviceId) {
    // First login — lock device
    updates.deviceId = deviceId;
    updates.firstLoginAt = user.firstLoginAt || Date.now();
  } else if (user.deviceId && deviceId && user.deviceId !== deviceId) {
    await secLog('DEVICE_MISMATCH', { ip, code: cleanCode, old: user.deviceId, new: deviceId });
    return res.json({ ok: false, msg: 'Yeh code doosre phone pe use ho chuka hai. Admin se contact karo.' });
  }

  if (user.coins === undefined) updates.coins = 0;
  await updateUser(cleanCode, updates);

  return res.json({
    ok: true,
    user: { code: user.code, name: user.name, coins: user.coins || 0 },
    settings
  });
});

// ── VERIFY SESSION (auto-login) ────────────────────────────
app.post('/verify', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const cleanCode = clean(code).toUpperCase();
  const [user, settings] = await Promise.all([getUser(cleanCode), getSettings()]);
  if (!user || user.banned) return res.json({ ok: false, msg: 'Session expire — dobara login karo' });
  return res.json({
    ok: true,
    user: { code: user.code, name: user.name, coins: user.coins || 0 },
    settings
  });
});

// ── ROUND INFO ─────────────────────────────────────────────
app.get('/round', async (req, res) => {
  const [round, settings] = await Promise.all([getCurrentRound(), getSettings()]);
  if (!round) return res.json({ ok: true, round: null, settings });
  return res.json({
    ok: true, settings,
    round: {
      id: round.id, status: round.status, startedAt: round.startedAt,
      betEndsAt: round.startedAt + 40 * 60 * 1000,
      roundEndsAt: round.startedAt + 60 * 60 * 1000,
      winNum: round.status === 'result' ? round.winNum : null
    }
  });
});

// ── MY BET STATUS ──────────────────────────────────────────
app.post('/mybetStatus', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const cleanCode = clean(code).toUpperCase();

  const [currentRound, settings] = await Promise.all([getCurrentRound(), getSettings()]);
  const user = await getUser(cleanCode);
  const coins = user ? (user.coins || 0) : 0;

  let round = currentRound;
  let bet = null;

  if (currentRound) {
    bet = await getUserBetInRound(currentRound.id, cleanCode);
  } else {
    // No active round — show last result
    try {
      const last = await C.rounds().where('status', '==', 'result').orderBy('resultAt', 'desc').limit(1).get();
      if (!last.empty) {
        round = { ...last.docs[0].data(), id: last.docs[0].id };
        const b = await C.bets().where('roundId', '==', round.id).where('userCode', '==', cleanCode).limit(1).get();
        if (!b.empty) bet = { ...b.docs[0].data(), id: b.docs[0].id };
      }
    } catch(e) {}
  }

  if (!round) return res.json({ ok: true, bet: null, round: null, settings, coins });

  const activeRound = currentRound || round;
  const ri = {
    id: activeRound.id, status: activeRound.status, startedAt: activeRound.startedAt,
    betEndsAt: activeRound.startedAt + 40 * 60 * 1000,
    roundEndsAt: activeRound.startedAt + 60 * 60 * 1000,
    winNum: activeRound.status === 'result' ? activeRound.winNum : null
  };
  return res.json({ ok: true, bet, round: ri, settings, coins });
});

// ── PLACE BET ──────────────────────────────────────────────
app.post('/bet', async (req, res) => {
  const { code, number, amount, utr, userUpi } = req.body;
  const ip = getIP(req);

  if (!code || number === undefined || !amount || !utr || !userUpi)
    return res.json({ ok: false, msg: 'Saari details daalo' });

  if (!checkRate('bet:' + ip, 5, 60000))
    return res.json({ ok: false, msg: 'Bahut zyada attempts. Thodi der baad try karo.' });

  const cleanCode = clean(code).toUpperCase();
  const num = parseInt(number);
  if (isNaN(num) || num < 0 || num > 9)
    return res.json({ ok: false, msg: 'Number 0-9 ke beech hona chahiye' });

  const cleanUTR = utr.toString().trim().replace(/\s/g, '');
  if (!/^\d{6,20}$/.test(cleanUTR))
    return res.json({ ok: false, msg: 'UTR sirf numbers hona chahiye (6-20 digit)' });

  const cleanUpi = clean(userUpi);
  if (!cleanUpi) return res.json({ ok: false, msg: 'Apni UPI ID daalo' });

  const [user, round, settings, alreadyUsed] = await Promise.all([
    getUser(cleanCode), getCurrentRound(), getSettings(), utrExists(cleanUTR)
  ]);

  if (!user)   return res.json({ ok: false, msg: 'Invalid code' });
  if (!round)  return res.json({ ok: false, msg: 'Koi round nahi chala abhi' });
  if (round.status !== 'open') return res.json({ ok: false, msg: 'Betting band ho gayi' });

  const amt = parseInt(amount);
  if (isNaN(amt) || amt < settings.minBet || amt > settings.maxBet)
    return res.json({ ok: false, msg: `Amount ₹${settings.minBet}-${settings.maxBet} ke beech hona chahiye` });

  if (alreadyUsed) return res.json({ ok: false, msg: 'Yeh UTR pehle use ho chuka hai' });

  const existing = await getUserBetInRound(round.id, cleanCode);
  if (existing) return res.json({ ok: false, msg: 'Aapki bet pehle se hai is round mein' });

  const betId = uid();
  await C.bets().doc(betId).set({
    id: betId, roundId: round.id,
    userCode: cleanCode, userName: user.name,
    number: num, amount: amt,
    utr: cleanUTR, userUpi: cleanUpi,
    status: 'pending', placedAt: Date.now(),
    won: null, winAmount: null, paid: false
  });

  return res.json({ ok: true, bet: { id: betId, number: num, amount: amt, status: 'pending' } });
});

// ── MY HISTORY ─────────────────────────────────────────────
app.post('/myhistory', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const cleanCode = clean(code).toUpperCase();
  try {
    const snap = await C.bets()
      .where('userCode', '==', cleanCode)
      .where('status', 'in', ['approved', 'pending'])
      .orderBy('placedAt', 'desc')
      .limit(30).get();
    const bets = snap.docs.map(d => d.data());
    // Get round results
    const roundIds = [...new Set(bets.map(b => b.roundId))];
    const rounds = {};
    await Promise.all(roundIds.map(async rid => {
      const r = await C.rounds().doc(rid).get();
      if (r.exists) rounds[rid] = r.data();
    }));
    const history = bets.map(b => {
      const r = rounds[b.roundId] || {};
      return { roundId: b.roundId, resultAt: r.resultAt || null, winNum: r.winNum || null, myNumber: b.number, myAmount: b.amount, won: b.won, winAmount: b.winAmount || 0, status: b.status };
    });
    return res.json({ ok: true, history });
  } catch(e) { return res.json({ ok: true, history: [] }); }
});

// ═══════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════

// ── ADMIN DATA ─────────────────────────────────────────────
app.get('/admin/data', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  try {
    const [round, settings, userCount, pendingBetsSnap] = await Promise.all([
      getCurrentRound(),
      getSettings(),
      C.users().count().get(),
      C.bets().where('status', '==', 'pending').count().get(),
    ]);

    let bets = [], numStats = null, currentBets = 0, currentAmount = 0;
    if (round) {
      bets = await getBetsByRound(round.id);
      numStats = {};
      for (let i = 0; i <= 9; i++) numStats[i] = { count: 0, total: 0, bets: [] };
      bets.filter(b => b.status === 'approved').forEach(b => {
        numStats[b.number].count++;
        numStats[b.number].total += b.amount;
        numStats[b.number].bets.push({ name: b.userName, code: b.userCode, amount: b.amount, upi: b.userUpi });
        currentBets++;
        currentAmount += b.amount;
      });
    }

    const usersSnap = await C.users().orderBy('createdAt', 'desc').limit(100).get();
    const users = usersSnap.docs.map(d => ({ ...d.data(), code: d.id }));
    const totalRoundsSnap = await C.rounds().where('status', '==', 'result').count().get();

    const ri = round ? {
      ...round, bets,
      betEndsAt: round.startedAt + 40 * 60 * 1000,
      roundEndsAt: round.startedAt + 60 * 60 * 1000
    } : null;

    return res.json({
      ok: true, users, round: ri, numStats, settings,
      pendingBets: pendingBetsSnap.data().count,
      stats: {
        totalUsers: userCount.data().count,
        totalRounds: totalRoundsSnap.data().count,
        currentBets, currentAmount
      }
    });
  } catch(e) {
    return res.status(500).json({ ok: false, msg: e.message });
  }
});

// ── ROUND CONTROLS ─────────────────────────────────────────
app.post('/admin/round/start', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const existing = await getCurrentRound();
  if (existing) return res.json({ ok: false, msg: 'Pehle current round finish karo' });
  const roundId = uid();
  const round = { id: roundId, status: 'open', startedAt: Date.now(), closedAt: null, resultAt: null, winNum: null };
  await C.rounds().doc(roundId).set(round);
  await setCurrentRound(roundId);
  res.json({ ok: true, round });
});

app.post('/admin/round/close', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const round = await getCurrentRound();
  if (!round || round.status !== 'open') return res.json({ ok: false, msg: 'Koi open round nahi' });
  await C.rounds().doc(round.id).set({ status: 'closed', closedAt: Date.now() }, { merge: true });
  res.json({ ok: true });
});

app.post('/admin/round/result', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { winNum } = req.body;
  const num = parseInt(winNum);
  if (isNaN(num) || num < 0 || num > 9) return res.json({ ok: false, msg: '0-9 mein se number daalo' });

  const [round, settings] = await Promise.all([getCurrentRound(), getSettings()]);
  if (!round || round.status === 'result') return res.json({ ok: false, msg: 'Round ready nahi' });

  const mult   = settings.multiplier || 9;
  const bets   = await getBetsByRound(round.id);
  const winners = [];

  await Promise.all(bets.map(async b => {
    if (b.status === 'approved') {
      const won       = b.number === num;
      const winAmount = won ? b.amount * mult : 0;
      await C.bets().doc(b.id).set({ won, winAmount }, { merge: true });
      if (won) {
        await updateUser(b.userCode, { coins: FieldValue.increment(winAmount) });
        winners.push({ name: b.userName, code: b.userCode, amount: winAmount });
      }
    }
  }));

  await C.rounds().doc(round.id).set({ status: 'result', winNum: num, resultAt: Date.now() }, { merge: true });
  await setCurrentRound(null);
  res.json({ ok: true, winNum: num, winners });
});

// ── BET VERIFY ─────────────────────────────────────────────
app.post('/admin/bet/verify', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { betId, action } = req.body;
  try {
    const status = action === 'approve' ? 'approved' : 'rejected';
    await C.bets().doc(betId).set({ status, verifiedAt: Date.now() }, { merge: true });
    return res.json({ ok: true, status });
  } catch(e) { return res.json({ ok: false, msg: 'Bet nahi mili' }); }
});

// ── HISTORY ────────────────────────────────────────────────
app.get('/admin/history', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  try {
    const snap = await C.rounds().where('status', '==', 'result').orderBy('resultAt', 'desc').limit(50).get();
    const rounds = snap.docs.map(d => ({ ...d.data(), id: d.id }));
    const history = await Promise.all(rounds.map(async r => {
      const bets = await getBetsByRound(r.id);
      return { ...r, bets };
    }));
    res.json({ ok: true, history });
  } catch(e) { res.json({ ok: true, history: [] }); }
});

app.delete('/admin/history/:roundId', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const roundId = req.params.roundId;
  const betsSnap = await C.bets().where('roundId', '==', roundId).get();
  const batch = db.batch();
  betsSnap.docs.forEach(d => batch.delete(d.ref));
  batch.delete(C.rounds().doc(roundId));
  await batch.commit();
  res.json({ ok: true });
});

app.delete('/admin/history', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const snap = await C.rounds().where('status', '==', 'result').get();
  const batch = db.batch();
  snap.docs.forEach(d => batch.delete(d.ref));
  await batch.commit();
  res.json({ ok: true });
});

// ── SETTINGS ───────────────────────────────────────────────
app.post('/admin/settings', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { upiId, upiName, minBet, maxBet, multiplier, tgLink, minWithdraw, coinRate } = req.body;
  const current = await getSettings();
  const updated = { ...current };
  if (upiId     !== undefined) updated.upiId      = clean(upiId);
  if (upiName   !== undefined) updated.upiName    = clean(upiName);
  if (tgLink    !== undefined) updated.tgLink     = clean(tgLink);
  if (minBet    !== undefined && minBet    !== '') updated.minBet     = parseInt(minBet);
  if (maxBet    !== undefined && maxBet    !== '') updated.maxBet     = parseInt(maxBet);
  if (multiplier!== undefined && multiplier!== '') updated.multiplier = Math.min(parseInt(multiplier), 20);
  if (minWithdraw !== undefined && minWithdraw !== '') updated.minWithdraw = parseInt(minWithdraw);
  if (coinRate  !== undefined && coinRate  !== '') updated.coinRate   = parseFloat(coinRate);
  await C.settings().doc('main').set(updated, { merge: true });
  res.json({ ok: true, settings: updated });
});

// ── USER MANAGEMENT ────────────────────────────────────────
app.post('/admin/user', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { name } = req.body;
  const code = genCode();
  await C.users().doc(code).set({
    code, name: clean(name || 'User'),
    createdAt: Date.now(), deviceId: null, coins: 0, banned: false
  });
  res.json({ ok: true, code, name: clean(name || 'User') });
});

app.delete('/admin/user/:code', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  await C.users().doc(req.params.code.toUpperCase()).delete();
  res.json({ ok: true });
});

app.post('/admin/user/resetdevice', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code } = req.body;
  const user = await getUser(code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  await updateUser(code, { deviceId: null });
  res.json({ ok: true });
});

app.post('/admin/user/ban', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code, blockDev } = req.body;
  const user = await getUser(code);
  if (!user) return res.json({ ok: false });
  await updateUser(code, { banned: true, bannedAt: Date.now() });
  if (blockDev && user.deviceId) await blockDevice(user.deviceId);
  await secLog('USER_BANNED', { code, blockDev: blockDev || false });
  res.json({ ok: true });
});

app.post('/admin/user/unban', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code } = req.body;
  await updateUser(code, { banned: false });
  res.json({ ok: true });
});

app.get('/admin/user/:code', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const code = req.params.code.toUpperCase();
  const user = await getUser(code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  const betsSnap = await C.bets().where('userCode', '==', code).orderBy('placedAt', 'desc').limit(20).get();
  const bets = betsSnap.docs.map(d => ({ ...d.data(), id: d.id }));
  const approved = bets.filter(b => b.status === 'approved');
  res.json({
    ok: true,
    user: { code: user.code, name: user.name, coins: user.coins || 0, banned: user.banned || false, deviceId: user.deviceId || null, createdAt: user.createdAt, lastLoginAt: user.lastLoginAt, lastLoginIP: user.lastLoginIP },
    bets: { total: approved.length, wins: approved.filter(b => b.won).length, losses: approved.filter(b => b.won === false).length },
    betHistory: bets,
    securityFlags: [], risk: { score: 0, reasons: [] }
  });
});

app.get('/admin/search', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const q = clean(req.query.q || '').toUpperCase();
  if (!q) return res.json({ ok: true, results: [] });
  try {
    const byCode = await C.users().where('__name__', '>=', q).where('__name__', '<=', q + '\uf8ff').limit(20).get();
    const results = byCode.docs.map(d => ({ ...d.data(), code: d.id }));
    if (results.length < 5) {
      const byName = await C.users().where('name', '>=', q).where('name', '<=', q + '\uf8ff').limit(10).get();
      byName.docs.forEach(d => { if (!results.find(r => r.code === d.id)) results.push({ ...d.data(), code: d.id }); });
    }
    res.json({ ok: true, results: results.slice(0, 20).map(u => ({ code: u.code, name: u.name, coins: u.coins || 0, banned: u.banned || false, lastLoginAt: u.lastLoginAt })) });
  } catch(e) { res.json({ ok: true, results: [] }); }
});

// ── SECURITY LOG ───────────────────────────────────────────
app.get('/admin/seclog', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const snap = await C.seclog().orderBy('at', 'desc').limit(200).get();
  res.json({ ok: true, log: snap.docs.map(d => ({ ...d.data(), id: d.id })) });
});

// Block unknown routes
app.use((req, res) => res.status(404).json({ ok: false, msg: 'Not found' }));

app.listen(PORT, '0.0.0.0', () => console.log('NUMBET v6.0 Firebase on port ' + PORT));
