const express = require('express');
const cors = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const { getFirestore } = require('firebase-admin/firestore');
const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'ADMIN2026';
// ─── FIREBASE INIT ────────────────────────────────────────
const firebaseApp = initializeApp({
initializeApp({
  credential: cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
    privateKey: process.env.FIREBASE_PRIVATE_KEY
      ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
      : undefined,
  }),
});
const db = getFirestore(firebaseApp);
const DATA_DOC = db.collection('numbet').doc('data');
const firestore = getFirestore();
const DATA_DOC = firestore.collection('app').doc('data');
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
-1
+0
    const snap = await DATA_DOC.get();
    if (snap.exists) {
      const d = snap.data();
      // Ensure nested arrays/objects exist
      if (!d.users) d.users = [];
      if (!d.rounds) d.rounds = [];
      if (!d.withdrawRequests) d.withdrawRequests = [];
-0
+1
      if (!d.blockedUTRs) d.blockedUTRs = [];
      if (!d.securityLog) d.securityLog = [];
      if (!d.settings) d.settings = defaultData().settings;
      if (!d.currentRoundId) d.currentRoundId = null;
      return d;
    }
  } catch (e) {
-0
+1
  if (!d.blockedDevices) d.blockedDevices = [];
  if (!d.blockedUTRs) d.blockedUTRs = [];
  if (!d.securityLog) d.securityLog = [];
  if (!d.settings) d.settings = defaultData().settings;
  if (!d.settings.minWithdraw) d.settings.minWithdraw = 300;
  if (!d.settings.coinRate) d.settings.coinRate = 1;
  if (!d.settings.maxDailyCoins) d.settings.maxDailyCoins = 50000;
-1
+0
  if (d.securityLog.length > 500) d.securityLog = d.securityLog.slice(0, 500);
}
// Get IP from request
function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
-98
+168
// ─── LOGIN ────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { code, deviceId } = req.body;
  const ip = getIP(req);
  if (!code) return res.json({ ok: false, msg: 'Code daalo' });
  const d = await load();
  ensureArrays(d);
  if (!checkRate('login:' + ip, 10, 60000)) {
    secLog(d, 'RATE_LIMIT', { ip, code: code.toUpperCase(), action: 'login' });
    await save(d);
    return res.json({ ok: false, msg: 'Bahut zyada attempts. 1 minute baad try karo.' });
  }
  const user = d.users.find((u) => u.code === code.trim().toUpperCase());
  if (!user) {
    secLog(d, 'LOGIN_FAIL', { ip, code: code.trim().toUpperCase() });
    await save(d);
    return res.json({ ok: false, msg: 'Galat code — Telegram se lo: @Winx1010' });
  }
  if (deviceId && d.blockedDevices.includes(deviceId)) {
    secLog(d, 'BLOCKED_DEVICE_LOGIN', { ip, code: user.code, deviceId });
    await save(d);
    return res.json({ ok: false, msg: 'Yeh device block hai. Admin se contact karo.' });
  }
  if (user.banned) {
    secLog(d, 'BANNED_USER_LOGIN', { ip, code: user.code });
    await save(d);
    return res.json({ ok: false, msg: 'Aapka account suspend hai. Admin se contact karo.' });
  }
  if (!user.deviceId && deviceId) {
    user.deviceId = deviceId;
    user.firstLoginAt = user.firstLoginAt || Date.now();
    user.lastLoginAt = Date.now();
    user.lastLoginIP = ip;
    await save(d);
  } else if (user.deviceId && deviceId && user.deviceId !== deviceId) {
    secLog(d, 'DEVICE_MISMATCH', {
      ip,
      code: user.code,
      savedDevice: user.deviceId,
      newDevice: deviceId,
  try {
    const { code, deviceId } = req.body;
    const ip = getIP(req);
    if (!code) return res.json({ ok: false, msg: 'Code daalo' });
    const d = await load();
    ensureArrays(d);
    if (!checkRate('login:' + ip, 10, 60000)) {
      secLog(d, 'RATE_LIMIT', { ip, code: code.toUpperCase(), action: 'login' });
      await save(d);
      return res.json({ ok: false, msg: 'Bahut zyada attempts. 1 minute baad try karo.' });
    }
    const user = d.users.find((u) => u.code === code.trim().toUpperCase());
    if (!user) {
      secLog(d, 'LOGIN_FAIL', { ip, code: code.trim().toUpperCase() });
      await save(d);
      return res.json({ ok: false, msg: 'Galat code — Telegram se lo: @Winx1010' });
    }
    if (deviceId && d.blockedDevices.includes(deviceId)) {
      secLog(d, 'BLOCKED_DEVICE_LOGIN', { ip, code: user.code, deviceId });
      await save(d);
      return res.json({ ok: false, msg: 'Yeh device block hai. Admin se contact karo.' });
    }
    if (user.banned) {
      secLog(d, 'BANNED_USER_LOGIN', { ip, code: user.code });
      await save(d);
      return res.json({ ok: false, msg: 'Aapka account suspend hai. Admin se contact karo.' });
    }
    if (!user.deviceId && deviceId) {
      user.deviceId = deviceId;
      user.firstLoginAt = user.firstLoginAt || Date.now();
      user.lastLoginAt = Date.now();
      user.lastLoginIP = ip;
      await save(d);
    } else if (user.deviceId && deviceId && user.deviceId !== deviceId) {
      secLog(d, 'DEVICE_MISMATCH', {
        ip, code: user.code, savedDevice: user.deviceId, newDevice: deviceId,
      });
      await save(d);
      return res.json({ ok: false, msg: 'Yeh code doosre phone pe use ho chuka hai' });
    } else {
      user.lastLoginAt = Date.now();
      user.lastLoginIP = ip;
      await save(d);
    }
    if (user.coins === undefined) user.coins = 0;
    return res.json({
      ok: true,
      user: { code: user.code, name: user.name, coins: user.coins || 0 },
      settings: d.settings,
    });
    await save(d);
    return res.json({ ok: false, msg: 'Yeh code doosre phone pe use ho chuka hai' });
  } else {
    user.lastLoginAt = Date.now();
    user.lastLoginIP = ip;
    await save(d);
  }
  if (user.coins === undefined) user.coins = 0;
  return res.json({
    ok: true,
    user: { code: user.code, name: user.name, coins: user.coins || 0 },
    settings: d.settings,
  });
  } catch (e) {
    console.error('/login error:', e.message);
    return res.json({ ok: false, msg: 'Server error' });
  }
});
app.post('/verify', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = await load();
  ensureArrays(d);
  const user = d.users.find((u) => u.code === code.trim().toUpperCase());
  if (!user || user.banned)
    return res.json({ ok: false, msg: 'Session expire — dobara login karo' });
  if (user.coins === undefined) {
    user.coins = 0;
    await save(d);
  }
  return res.json({
    ok: true,
    user: { code: user.code, name: user.name, coins: user.coins || 0 },
    settings: d.settings,
  });
  try {
    const { code } = req.body;
    if (!code) return res.json({ ok: false });
    const d = await load();
    ensureArrays(d);
    const user = d.users.find((u) => u.code === code.trim().toUpperCase());
    if (!user || user.banned)
      return res.json({ ok: false, msg: 'Session expire — dobara login karo' });
    if (user.coins === undefined) { user.coins = 0; await save(d); }
    return res.json({
      ok: true,
      user: { code: user.code, name: user.name, coins: user.coins || 0 },
      settings: d.settings,
    });
  } catch (e) {
    console.error('/verify error:', e.message);
    return res.json({ ok: false, msg: 'Server error' });
  }
});
// ─── ROUND INFO (PUBLIC) ─────────────────────────────────
app.get('/round', async (req, res) => {
  const d = await load();
  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: true, round: null, settings: d.settings });
  const info = {
    id: round.id,
    status: round.status,
    startedAt: round.startedAt,
    betEndsAt: round.startedAt + 40 * 60 * 1000,
    roundEndsAt: round.startedAt + 60 * 60 * 1000,
    winNum: round.status === 'result' ? round.winNum : null,
  };
  return res.json({ ok: true, round: info, settings: d.settings });
  try {
    const d = await load();
    const round = getCurrentRound(d);
    if (!round) return res.json({ ok: true, round: null, settings: d.settings });
    const info = {
      id: round.id, status: round.status, startedAt: round.startedAt,
      betEndsAt: round.startedAt + 40 * 60 * 1000,
      roundEndsAt: round.startedAt + 60 * 60 * 1000,
      winNum: round.status === 'result' ? round.winNum : null,
    };
    return res.json({ ok: true, round: info, settings: d.settings });
  } catch (e) {
    console.error('/round error:', e.message);
    return res.json({ ok: false, msg: 'Server error' });
  }
});
// ─── MY BET STATUS ───────────────────────────────────────
app.post('/mybetStatus', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = await load();
  ensureArrays(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find((u) => u.code === cleanCode);
  let round = getCurrentRound(d);
  if (!round) {
    const done = d.rounds.filter((r) => r.status === 'result');
    round = done.length ? done[done.length - 1] : null;
  }
  if (!round)
  try {
    const { code } = req.body;
    if (!code) return res.json({ ok: false });
    const d = await load();
    ensureArrays(d);
    const cleanCode = code.trim().toUpperCase();
    const user = d.users.find((u) => u.code === cleanCode);
    let round = getCurrentRound(d);
    if (!round) {
      const done = d.rounds.filter((r) => r.status === 'result');
      round = done.length ? done[done.length - 1] : null;
    }
    if (!round)
      return res.json({
        ok: true, bet: null, round: null,
        settings: d.settings, coins: user ? user.coins || 0 : 0,
      });
    const bet = (round.bets || []).find((b) => b.userCode === cleanCode);
    const ri = {
      id: round.id, status: round.status, startedAt: round.startedAt,
      betEndsAt: round.startedAt + 40 * 60 * 1000,
      roundEndsAt: round.startedAt + 60 * 60 * 1000,
      winNum: round.status === 'result' ? round.winNum : null,
    };
    return res.json({
      ok: true, bet: bet || null, round: ri,
      settings: d.settings, coins: user ? user.coins || 0 : 0,
    });
  } catch (e) {
    console.error('/mybetStatus error:', e.message);
    return res.json({ ok: false, msg: 'Server error' });
  }
});
// ─── MY HISTORY ──────────────────────────────────────────
app.post('/myhistory', async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.json({ ok: false });
    const d = await load();
    const cleanCode = code.trim().toUpperCase();
    const history = d.rounds
      .filter((r) => r.status === 'result')
      .map((r) => {
        const bet = (r.bets || []).find((b) => b.userCode === cleanCode);
        if (!bet || bet.status === 'rejected') return null;
        return {
          roundId: r.id, resultAt: r.resultAt, winNum: r.winNum,
          myNumber: bet.number, myAmount: bet.amount,
          won: bet.won, winAmount: bet.winAmount || 0, status: bet.status,
        };
      })
      .filter(Boolean)
      .reverse()
      .slice(0, 50);
    return res.json({ ok: true, history });
  } catch (e) {
    console.error('/myhistory error:', e.message);
    return res.json({ ok: false, msg: 'Server error' });
  }
});
// ─── PLACE BET ───────────────────────────────────────────
app.post('/bet', async (req, res) => {
  try {
    const { code, number, amount } = req.body;
    const ip = getIP(req);
    if (!code || number === undefined || !amount)
      return res.json({ ok: false, msg: 'Saari details daalo' });
    const d = await load();
    ensureArrays(d);
    const cleanCode = code.trim().toUpperCase();
    const user = d.users.find((u) => u.code === cleanCode);
    if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });
    const round = getCurrentR...
[truncated]
[truncated]
[truncated]
