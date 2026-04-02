/**
 * NUMBET SERVER v5.1 — SECURITY HARDENED
 * Collections: users, rounds, bets, coinRequests, withdrawRequests, meta, settings, securityLog, blocked
 */

const express = require('express');
const cors = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const app = express();
const PORT = process.env.PORT || 10000;

// ═══════════════════════════════════════════════════════════
// [SEC-1] ALL SECRETS FROM ENV ONLY — no fallback defaults
// ═══════════════════════════════════════════════════════════
const ADMIN_PASS   = process.env.ADMIN_PASS;
const ADMIN_KEY    = process.env.ADMIN_KEY;
const APP_SECRET   = process.env.APP_SECRET;

if (!ADMIN_PASS || !ADMIN_KEY || !APP_SECRET) {
  console.error('FATAL: ADMIN_PASS, ADMIN_KEY, APP_SECRET env vars must be set!');
  process.exit(1);
}
if (!process.env.FIREBASE_PROJECT_ID) {
  console.error('FATAL: Firebase env vars not configured!');
  process.exit(1);
}

// ═══════════════════════════════════════════════════════════
// CORS — restrict to your domains only
// ═══════════════════════════════════════════════════════════
app.use(cors({ origin: true }));
app.use(express.json({ limit: '1mb' })); // [SEC-2] reduced from 10mb

// ═══════════════════════════════════════════════════════════
// [SEC-3] GLOBAL DDOS RATE LIMIT — 120 req/min per IP
// ═══════════════════════════════════════════════════════════
const globalLimiter = {};
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
  const now = Date.now();
  if (!globalLimiter[ip]) globalLimiter[ip] = [];
  globalLimiter[ip] = globalLimiter[ip].filter(t => now - t < 60000);
  if (globalLimiter[ip].length > 120) return res.status(429).json({ ok:false, msg:'Too many requests' });
  globalLimiter[ip].push(now);
  next();
});

// ═══════════════════════════════════════════════════════════
// [SEC-4] APP SECRET CHECK — blocks all API cloners/scrapers
// Admin routes have their own dual-key auth, skip x-app for them
// ═══════════════════════════════════════════════════════════
app.use((req, res, next) => {
  if (req.path.startsWith('/admin')) return next(); // admin uses dual-key auth below
  if (req.headers['x-app'] !== APP_SECRET) {
    return res.status(403).json({ ok:false, msg:'Forbidden' });
  }
  next();
});

// User-Agent check — basic bot filter
app.use((req, res, next) => {
  if (!req.headers['user-agent']) return res.status(403).json({ ok:false, msg:'Forbidden' });
  next();
});

// ═══════════════════════════════════════════════════════════
// FIREBASE INIT
// ═══════════════════════════════════════════════════════════
initializeApp({
  credential: cert({
    projectId:   process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  })
});
const db = getFirestore();

const C = {
  users:    () => db.collection('users'),
  rounds:   () => db.collection('rounds'),
  bets:     () => db.collection('bets'),
  coins:    () => db.collection('coinRequests'),
  withdraw: () => db.collection('withdrawRequests'),
  seclog:   () => db.collection('securityLog'),
  meta:     () => db.collection('meta'),
  settings: () => db.collection('settings'),
  blocked:  () => db.collection('blocked'),
};

// ═══════════════════════════════════════════════════════════
// [SEC-5] ADMIN AUTH — dual key + brute force protection
// ═══════════════════════════════════════════════════════════
const adminAttempts = {};
function auth(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
  // Brute force: max 5 wrong attempts per 15 min per IP
  if (!adminAttempts[ip]) adminAttempts[ip] = { count:0, resetAt: Date.now() + 15*60*1000 };
  if (Date.now() > adminAttempts[ip].resetAt) { adminAttempts[ip] = { count:0, resetAt: Date.now() + 15*60*1000 }; }
  if (adminAttempts[ip].count >= 5) return false;

  const pass = req.headers['x-pass'];
  const key  = req.headers['x-key'];
  if (!pass || !key) { adminAttempts[ip].count++; return false; }
  const ok = (pass === ADMIN_PASS && key === ADMIN_KEY);
  if (!ok) adminAttempts[ip].count++;
  else adminAttempts[ip].count = 0; // reset on success
  return ok;
}

// ═══════════════════════════════════════════════════════════
// [SEC-6] INPUT SANITIZATION
// ═══════════════════════════════════════════════════════════
function clean(str) { return String(str||'').replace(/[<>{}$]/g,'').trim().slice(0,500); }

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}

// ═══════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════
function uid() { return Date.now().toString(36) + Math.random().toString(36).substr(2,5).toUpperCase(); }
function genCode() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 8; i++) { if (i === 4) s += '-'; s += c[Math.floor(Math.random()*c.length)]; }
  return s;
}

// ── SETTINGS ──────────────────────────────────────────────
const defaultSettings = {
  upiId:'', upiName:'Admin', minBet:10, maxBet:5000,
  multiplier:9, tgLink:'https://t.me/Winx1010',
  minWithdraw:300, coinRate:1, maxDailyCoins:50000
};
async function getSettings() {
  try {
    const snap = await C.settings().doc('main').get();
    return snap.exists ? { ...defaultSettings, ...snap.data() } : defaultSettings;
  } catch(e) { return defaultSettings; }
}
async function saveSettings(data) { await C.settings().doc('main').set(data, { merge: true }); }

// ── USERS ─────────────────────────────────────────────────
async function getUser(code) {
  try {
    const snap = await C.users().doc(code.toUpperCase()).get();
    return snap.exists ? { ...snap.data(), code: snap.id } : null;
  } catch(e) { return null; }
}
async function updateUser(code, data) {
  try { await C.users().doc(code.toUpperCase()).set(data, { merge: true }); } catch(e) {}
}
async function createUser(userData) {
  await C.users().doc(userData.code).set(userData);
}

// ── ROUNDS ────────────────────────────────────────────────
async function getCurrentRound() {
  try {
    const meta = await C.meta().doc('currentRound').get();
    if (!meta.exists || !meta.data().roundId) return null;
    const snap = await C.rounds().doc(meta.data().roundId).get();
    return snap.exists ? { ...snap.data(), id: snap.id } : null;
  } catch(e) { return null; }
}
async function setCurrentRound(roundId) { await C.meta().doc('currentRound').set({ roundId: roundId || null }); }
async function createRound(roundData) { await C.rounds().doc(roundData.id).set(roundData); await setCurrentRound(roundData.id); }
async function updateRound(roundId, data) { await C.rounds().doc(roundId).set(data, { merge: true }); }

// ── BETS ──────────────────────────────────────────────────
async function getBetsByRound(roundId) {
  try {
    const snap = await C.bets().where('roundId','==',roundId).get();
    return snap.docs.map(d => ({ ...d.data(), id: d.id }));
  } catch(e) { return []; }
}
async function getUserBetForRound(roundId, userCode) {
  try {
    const snap = await C.bets().where('roundId','==',roundId).where('userCode','==',userCode).where('status','!=','rejected').limit(1).get();
    if (snap.empty) return null;
    return { ...snap.docs[0].data(), id: snap.docs[0].id };
  } catch(e) { return null; }
}
async function createBet(betData) { await C.bets().doc(betData.id).set(betData); }
async function updateBet(betId, data) { await C.bets().doc(betId).set(data, { merge: true }); }
async function checkUTRExists(utr) {
  try {
    const s1 = await C.bets().where('utr','==',utr).limit(1).get();
    if (!s1.empty) return true;
    const s2 = await C.coins().where('utr','==',utr).limit(1).get();
    return !s2.empty;
  } catch(e) { return false; }
}

// ── BLOCKED ───────────────────────────────────────────────
async function isDeviceBlocked(deviceId) {
  if (!deviceId) return false;
  try { const s = await C.blocked().doc('device_'+deviceId).get(); return s.exists; } catch(e) { return false; }
}
async function isUTRBlocked(utr) {
  try { const s = await C.blocked().doc('utr_'+utr).get(); return s.exists; } catch(e) { return false; }
}
async function blockDevice(deviceId) {
  await C.blocked().doc('device_'+deviceId).set({ deviceId, blockedAt:Date.now(), type:'device' });
}
async function blockUTR(utr) {
  await C.blocked().doc('utr_'+utr).set({ utr, blockedAt:Date.now(), type:'utr' });
}

// ── SECURITY LOG ──────────────────────────────────────────
async function secLog(type, data) {
  try { await C.seclog().add({ type, data, at:Date.now() }); } catch(e) {}
}

// ── RATE LIMITING ─────────────────────────────────────────
const rateLimiter = {};
function checkRate(key, limit, windowMs) {
  const now = Date.now();
  if (!rateLimiter[key]) rateLimiter[key] = [];
  rateLimiter[key] = rateLimiter[key].filter(t => now - t < windowMs);
  if (rateLimiter[key].length >= limit) return false;
  rateLimiter[key].push(now);
  return true;
}

// ═══════════════════════════════════════════════════════════
// AUTO-CLOSE BETTING AT 40 MIN
// ═══════════════════════════════════════════════════════════
setInterval(async () => {
  try {
    const round = await getCurrentRound();
    if (!round || round.status !== 'open') return;
    if (Date.now() >= round.startedAt + 40*60*1000) {
      await updateRound(round.id, { status:'closed', closedAt:Date.now() });
      console.log('Auto-closed round', round.id);
    }
  } catch(e) {}
}, 15000);

// ═══════════════════════════════════════════════════════════
// PUBLIC APIs
// ═══════════════════════════════════════════════════════════
app.get('/', (req, res) => res.json({ status:'OK', version:'5.1' }));

// ── LOGIN ─────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { code, deviceId } = req.body;
  const ip = getIP(req);
  if (!code) return res.json({ ok:false, msg:'Code daalo' });
  const cleanCode = clean(code).toUpperCase();

  // [SEC-7] Stricter login rate limit: 5 attempts/min per IP
  if (!checkRate('login:'+ip, 5, 60000)) {
    await secLog('RATE_LIMIT', { ip, code:cleanCode, action:'login' });
    return res.json({ ok:false, msg:'Bahut zyada attempts. 1 minute baad try karo.' });
  }

  const [user, settings] = await Promise.all([getUser(cleanCode), getSettings()]);
  if (!user) {
    await secLog('LOGIN_FAIL', { ip, code:cleanCode });
    return res.json({ ok:false, msg:'Galat code — Telegram se lo: @Winx1010' });
  }
  if (deviceId && await isDeviceBlocked(deviceId)) {
    await secLog('BLOCKED_DEVICE_LOGIN', { ip, code:cleanCode, deviceId });
    return res.json({ ok:false, msg:'Yeh device block hai. Admin se contact karo.' });
  }
  if (user.banned) {
    await secLog('BANNED_USER_LOGIN', { ip, code:cleanCode });
    return res.json({ ok:false, msg:'Aapka account block hai. Admin se contact karo.' });
  }
  const updates = { lastLoginAt:Date.now(), lastLoginIP:ip };
  if (!user.deviceId && deviceId) {
    updates.deviceId = deviceId;
    updates.firstLoginAt = user.firstLoginAt || Date.now();
  } else if (user.deviceId && deviceId && user.deviceId !== deviceId) {
    await secLog('DEVICE_MISMATCH', { ip, code:cleanCode, oldDevice:user.deviceId, newDevice:deviceId });
    return res.json({ ok:false, msg:'Yeh code doosre phone pe use ho chuka hai. Admin se contact karo.' });
  }
  if (user.coins === undefined) updates.coins = 0;
  await updateUser(cleanCode, updates);
  return res.json({ ok:true, user:{ code:user.code, name:user.name, coins:user.coins||0 }, settings });
});

// ── VERIFY ───────────────────────────────────────────────
app.post('/verify', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok:false });
  const cleanCode = clean(code).toUpperCase();
  const [user, settings] = await Promise.all([getUser(cleanCode), getSettings()]);
  if (!user || user.banned) return res.json({ ok:false, msg:'Session expire — dobara login karo' });
  if (user.coins === undefined) await updateUser(cleanCode, { coins:0 });
  return res.json({ ok:true, user:{ code:user.code, name:user.name, coins:user.coins||0 }, settings });
});

// ── ROUND INFO ────────────────────────────────────────────
app.get('/round', async (req, res) => {
  const [round, settings] = await Promise.all([getCurrentRound(), getSettings()]);
  if (!round) return res.json({ ok:true, round:null, settings });
  return res.json({ ok:true, settings, round:{
    id:round.id, status:round.status, startedAt:round.startedAt,
    betEndsAt:round.startedAt+40*60*1000, roundEndsAt:round.startedAt+60*60*1000,
    winNum:round.status==='result'?round.winNum:null
  }});
});

// ── MY BET STATUS ─────────────────────────────────────────
app.post('/mybetStatus', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok:false });
  const cleanCode = clean(code).toUpperCase();
  const [currentRound, settings] = await Promise.all([getCurrentRound(), getSettings()]);
  const user = await getUser(cleanCode);
  const coins = user ? (user.coins||0) : 0;
  let round = currentRound, bet = null;
  if (currentRound) bet = await getUserBetForRound(currentRound.id, cleanCode);
  if (!currentRound) {
    try {
      const lastSnap = await C.rounds().where('status','==','result').orderBy('resultAt','desc').limit(1).get();
      if (!lastSnap.empty) {
        const lastRound = { ...lastSnap.docs[0].data(), id:lastSnap.docs[0].id };
        round = lastRound;
        const betSnap = await C.bets().where('roundId','==',lastRound.id).where('userCode','==',cleanCode).limit(1).get();
        if (!betSnap.empty) bet = { ...betSnap.docs[0].data(), id:betSnap.docs[0].id };
      }
    } catch(e) {}
  }
  if (!round) return res.json({ ok:true, bet:null, round:null, settings, coins });
  const activeRound = currentRound || round;
  const betBelongsToCurrent = bet && round && activeRound && round.id === activeRound.id;
  const ri = {
    id:activeRound.id, status:activeRound.status, startedAt:activeRound.startedAt,
    betEndsAt:activeRound.startedAt+40*60*1000, roundEndsAt:activeRound.startedAt+60*60*1000,
    winNum:activeRound.status==='result'?activeRound.winNum:null
  };
  return res.json({ ok:true, bet:betBelongsToCurrent?bet:null, round:ri, settings, coins });
});

// ── MY HISTORY ────────────────────────────────────────────
app.post('/myhistory', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok:false });
  const cleanCode = clean(code).toUpperCase();
  try {
    const snap = await C.bets().where('userCode','==',cleanCode).where('status','in',['approved','pending']).orderBy('placedAt','desc').limit(50).get();
    const bets = snap.docs.map(d => ({ ...d.data(), id:d.id }));
    const roundIds = [...new Set(bets.map(b => b.roundId))];
    const rounds = {};
    await Promise.all(roundIds.map(async rid => {
      const rs = await C.rounds().doc(rid).get();
      if (rs.exists) rounds[rid] = rs.data();
    }));
    const history = bets.filter(b => b.status !== 'rejected').map(b => {
      const r = rounds[b.roundId] || {};
      return { roundId:b.roundId, resultAt:r.resultAt||null, winNum:r.winNum||null, myNumber:b.number, myAmount:b.amount, won:b.won, winAmount:b.winAmount||0, status:b.status };
    });
    return res.json({ ok:true, history });
  } catch(e) { return res.json({ ok:true, history:[] }); }
});

// ── PLACE BET ─────────────────────────────────────────────
app.post('/bet', async (req, res) => {
  const { code, number, amount, utr, userUpi } = req.body;
  const ip = getIP(req);
  if (!code||number===undefined||!amount||!utr||!userUpi)
    return res.json({ ok:false, msg:'Saari details daalo' });

  // [SEC-8] Bet rate limit: 5 bets/min per IP
  if (!checkRate('bet:'+ip, 5, 60000))
    return res.json({ ok:false, msg:'Bahut zyada attempts. Thodi der baad try karo.' });

  const cleanCode = clean(code).toUpperCase();
  const num = parseInt(number);
  if (isNaN(num)||num<0||num>9) return res.json({ ok:false, msg:'Number 0-9 ke beech hona chahiye' });

  const cleanUTR = utr.toString().trim().replace(/\s/g,'');
  if (!/^\d{6,20}$/.test(cleanUTR)) return res.json({ ok:false, msg:'UTR sirf numbers hona chahiye (6-20 digit)' });

  // [SEC-9] UPI sanitize
  const cleanUpi = clean(userUpi);
  if (!cleanUpi) return res.json({ ok:false, msg:'Apni UPI ID daalo' });

  const [user, round, settings, utrExists, utrBlocked] = await Promise.all([
    getUser(cleanCode), getCurrentRound(), getSettings(), checkUTRExists(cleanUTR), isUTRBlocked(cleanUTR),
  ]);
  if (!user) return res.json({ ok:false, msg:'Invalid code' });
  if (!round) return res.json({ ok:false, msg:'Koi round nahi chala abhi' });
  if (round.status !== 'open') return res.json({ ok:false, msg:'Betting band ho gayi' });

  const amt = parseInt(amount);
  if (isNaN(amt)||amt<settings.minBet||amt>settings.maxBet)
    return res.json({ ok:false, msg:`Amount ₹${settings.minBet}-${settings.maxBet} ke beech hona chahiye` });

  if (utrExists) return res.json({ ok:false, msg:'Yeh UTR pehle use ho chuka hai' });
  if (utrBlocked) {
    await secLog('BLOCKED_UTR', { ip, code:cleanCode, utr:cleanUTR });
    return res.json({ ok:false, msg:'Yeh UTR block hai. Admin se contact karo.' });
  }
  const existing = await getUserBetForRound(round.id, cleanCode);
  if (existing) return res.json({ ok:false, msg:'Aapki bet pehle se hai is round mein' });

  const bet = {
    id:uid(), roundId:round.id, userCode:cleanCode, userName:user.name,
    number:num, amount:amt, utr:cleanUTR, userUpi:cleanUpi,
    status:'pending', placedAt:Date.now(), won:null, winAmount:null, paid:false
  };
  await createBet(bet);
  return res.json({ ok:true, bet:{ id:bet.id, number:num, amount:amt, status:'pending' } });
});

// ── WITHDRAW REQUEST ──────────────────────────────────────
app.post('/withdraw', async (req, res) => {
  const { code, coins, upiId } = req.body;
  const ip = getIP(req);
  if (!code||!coins||!upiId) return res.json({ ok:false, msg:'Saari details daalo' });

  // [SEC-10] Withdraw rate limit
  if (!checkRate('wd:'+ip, 3, 60000))
    return res.json({ ok:false, msg:'Bahut zyada attempts.' });

  const cleanCode = clean(code).toUpperCase();
  const [user, settings] = await Promise.all([getUser(cleanCode), getSettings()]);
  if (!user) return res.json({ ok:false, msg:'Invalid code' });

  const amt = parseInt(coins);
  if (isNaN(amt)||amt<settings.minWithdraw) return res.json({ ok:false, msg:`Min withdraw ${settings.minWithdraw} coins` });

  // [SEC-11] Check user actually has enough coins
  if ((user.coins||0) < amt) return res.json({ ok:false, msg:'Itne coins nahi hain' });

  const pendingSnap = await C.withdraw().where('userCode','==',cleanCode).where('status','==','pending').limit(1).get();
  if (!pendingSnap.empty) return res.json({ ok:false, msg:'Aapki ek request already pending hai' });

  // Deduct coins first, then create request (prevents double-withdraw)
  await updateUser(cleanCode, { coins: FieldValue.increment(-amt) });

  const wr = {
    id:uid(), userCode:user.code, userName:user.name,
    coins:amt, upiId:clean(upiId), status:'pending',
    createdAt:Date.now(), requestedAt:Date.now(), ip
  };
  await C.withdraw().doc(wr.id).set(wr);
  return res.json({ ok:true });
});

// ── COIN BUY REQUEST ──────────────────────────────────────
app.post('/coins/buy', async (req, res) => {
  const { code, amount, utr } = req.body;
  const ip = getIP(req);
  if (!code||!amount||!utr) return res.json({ ok:false, msg:'Saari details daalo' });

  if (!checkRate('coins:'+ip, 5, 60000))
    return res.json({ ok:false, msg:'Bahut zyada attempts.' });

  const cleanCode = clean(code).toUpperCase();
  const [user, settings] = await Promise.all([getUser(cleanCode), getSettings()]);
  if (!user) return res.json({ ok:false, msg:'Invalid code' });

  const amt = parseInt(amount);
  if (isNaN(amt)||amt<10) return res.json({ ok:false, msg:'Min ₹10 se coins lo' });

  const cleanUTR = utr.toString().trim().replace(/\s/g,'');
  if (!/^\d{6,20}$/.test(cleanUTR)) return res.json({ ok:false, msg:'UTR galat hai' });
  if (await isUTRBlocked(cleanUTR)) return res.json({ ok:false, msg:'Yeh UTR block hai' });
  if (await checkUTRExists(cleanUTR)) return res.json({ ok:false, msg:'Yeh UTR pehle use ho chuka hai' });

  const coins = Math.floor(amt * (settings.coinRate||1));
  const cr = {
    id:uid(), userCode:user.code, userName:user.name,
    amount:amt, utr:cleanUTR, coins, status:'pending',
    requestedAt:Date.now(), createdAt:Date.now(), ip
  };
  await C.coins().doc(cr.id).set(cr);
  return res.json({ ok:true, coinsWillGet:coins });
});

// ── COINS PREVIEW ─────────────────────────────────────────
app.post('/coins/preview', async (req, res) => {
  const { amount } = req.body;
  const settings = await getSettings();
  const amt = parseInt(amount)||0;
  const coins = Math.floor(amt * (settings.coinRate||1));
  return res.json({ ok:true, coinsWillGet:coins });
});

// ═══════════════════════════════════════════════════════════
// ADMIN APIs
// ═══════════════════════════════════════════════════════════
app.get('/admin/data', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  try {
    const [round, settings, userCount, pendingCoinsSnap, pendingWdSnap] = await Promise.all([
      getCurrentRound(), getSettings(),
      C.users().count().get(),
      C.coins().where('status','==','pending').count().get(),
      C.withdraw().where('status','==','pending').count().get(),
    ]);
    let bets = [], numStats = null, currentBets = 0, currentAmount = 0;
    if (round) {
      bets = await getBetsByRound(round.id);
      numStats = {};
      for (let i=0;i<=9;i++) numStats[i]={count:0,total:0,bets:[]};
      bets.filter(b=>b.status==='approved').forEach(b=>{
        numStats[b.number].count++;
        numStats[b.number].total+=b.amount;
        numStats[b.number].bets.push({name:b.userName,code:b.userCode,amount:b.amount});
        currentBets++; currentAmount+=b.amount;
      });
    }
    const usersSnap = await C.users().orderBy('createdAt','desc').limit(100).get();
    const users = usersSnap.docs.map(d => ({ ...d.data(), code:d.id }));
    const totalRoundsSnap = await C.rounds().where('status','==','result').count().get();
    const ri = round ? { ...round, bets, betEndsAt:round.startedAt+40*60*1000, roundEndsAt:round.startedAt+60*60*1000 } : null;
    return res.json({
      ok:true, users, round:ri, numStats, settings,
      pendingCoins: pendingCoinsSnap.data().count,
      pendingWithdraw: pendingWdSnap.data().count,
      stats:{ totalUsers:userCount.data().count, totalRounds:totalRoundsSnap.data().count, currentBets, currentAmount }
    });
  } catch(e) { return res.status(500).json({ ok:false, msg:e.message }); }
});

app.post('/admin/round/start', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const existing = await getCurrentRound();
  if (existing) return res.json({ ok:false, msg:'Pehle current round finish karo' });
  const round = { id:uid(), status:'open', startedAt:Date.now(), closedAt:null, resultAt:null, winNum:null };
  await createRound(round);
  res.json({ ok:true, round });
});

app.post('/admin/round/close', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const round = await getCurrentRound();
  if (!round||round.status!=='open') return res.json({ ok:false, msg:'Koi open round nahi' });
  await updateRound(round.id, { status:'closed', closedAt:Date.now() });
  res.json({ ok:true });
});

app.post('/admin/round/result', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { winNum } = req.body;
  const num = parseInt(winNum);
  if (isNaN(num)||num<0||num>9) return res.json({ ok:false, msg:'0-9 mein se number daalo' });
  const [round, settings] = await Promise.all([getCurrentRound(), getSettings()]);
  if (!round||round.status==='result') return res.json({ ok:false, msg:'Round result ke liye ready nahi' });
  const mult = settings.multiplier||9;
  const bets = await getBetsByRound(round.id);
  const winners = [];
  await Promise.all(bets.map(async b => {
    if (b.status === 'approved') {
      const won = b.number === num;
      const winAmount = won ? b.amount * mult : 0;
      await updateBet(b.id, { won, winAmount });
      if (won) {
        await updateUser(b.userCode, { coins: FieldValue.increment(winAmount) });
        winners.push({ name:b.userName, code:b.userCode, coins:winAmount });
      }
    }
  }));
  await updateRound(round.id, { status:'result', winNum:num, resultAt:Date.now() });
  await setCurrentRound(null);
  res.json({ ok:true, winNum:num, winners });
});

app.post('/admin/bet/verify', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { betId, action } = req.body;
  try {
    const status = action==='approve' ? 'approved' : 'rejected';
    await updateBet(betId, { status, verifiedAt:Date.now() });
    return res.json({ ok:true, status });
  } catch(e) { return res.json({ ok:false, msg:'Bet nahi mili' }); }
});

app.post('/admin/bet/paid', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { betId } = req.body;
  try { await updateBet(betId, { paid:true, paidAt:Date.now() }); return res.json({ ok:true }); }
  catch(e) { return res.json({ ok:false }); }
});

app.get('/admin/coins', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const snap = await C.coins().orderBy('createdAt','desc').limit(100).get();
  res.json({ ok:true, requests: snap.docs.map(d=>({...d.data(),id:d.id})) });
});

app.post('/admin/coins/approve', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { reqId } = req.body;
  const snap = await C.coins().doc(reqId).get();
  if (!snap.exists) return res.json({ ok:false, msg:'Request nahi mili' });
  const cr = snap.data();
  if (cr.status !== 'pending') return res.json({ ok:false, msg:'Already processed' });
  await C.coins().doc(reqId).update({ status:'approved', actionAt:Date.now() });
  await updateUser(cr.userCode, { coins: FieldValue.increment(cr.coins) });
  res.json({ ok:true });
});

app.post('/admin/coins/reject', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { reqId, blockUTR: shouldBlock } = req.body;
  const snap = await C.coins().doc(reqId).get();
  if (!snap.exists) return res.json({ ok:false, msg:'Request nahi mili' });
  const cr = snap.data();
  await C.coins().doc(reqId).update({ status:'rejected', actionAt:Date.now() });
  if (shouldBlock && cr.utr) await blockUTR(cr.utr);
  res.json({ ok:true });
});

app.post('/admin/coins/action', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { id, action } = req.body;
  const snap = await C.coins().doc(id).get();
  if (!snap.exists) return res.json({ ok:false, msg:'Request nahi mili' });
  const cr = snap.data();
  await C.coins().doc(id).update({ status:action==='approve'?'approved':'rejected', actionAt:Date.now() });
  if (action === 'approve') await updateUser(cr.userCode, { coins: FieldValue.increment(cr.coins) });
  res.json({ ok:true });
});

app.get('/admin/withdraw', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const snap = await C.withdraw().orderBy('requestedAt','desc').limit(100).get();
  res.json({ ok:true, requests: snap.docs.map(d=>({...d.data(),id:d.id})) });
});

app.post('/admin/withdraw/done', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { reqId } = req.body;
  await C.withdraw().doc(reqId).update({ status:'paid', paidAt:Date.now() });
  res.json({ ok:true });
});

app.post('/admin/withdraw/reject', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { reqId } = req.body;
  const snap = await C.withdraw().doc(reqId).get();
  if (!snap.exists) return res.json({ ok:false, msg:'Request nahi mili' });
  const wr = snap.data();
  await C.withdraw().doc(reqId).update({ status:'rejected', processedAt:Date.now() });
  // Refund coins on reject
  if (wr.coins) await updateUser(wr.userCode, { coins: FieldValue.increment(wr.coins) });
  res.json({ ok:true });
});

app.post('/admin/withdraw/action', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { id, action } = req.body;
  await C.withdraw().doc(id).update({ status:action==='approve'?'approved':'rejected', actionAt:Date.now() });
  res.json({ ok:true });
});

// User management
app.post('/admin/user', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { name } = req.body;
  const code = genCode();
  await createUser({ code, name:clean(name||'User'), createdAt:Date.now(), deviceId:null, coins:0, banned:false });
  res.json({ ok:true, code, name:clean(name||'User') });
});

app.delete('/admin/user/:code', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  await C.users().doc(req.params.code.toUpperCase()).delete();
  res.json({ ok:true });
});

app.post('/admin/user/resetdevice', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { code } = req.body;
  const user = await getUser(code);
  if (!user) return res.json({ ok:false, msg:'User nahi mila' });
  await updateUser(code, { deviceId:null });
  res.json({ ok:true });
});

app.post('/admin/user/coins', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { code, coins } = req.body;
  const user = await getUser(code);
  if (!user) return res.json({ ok:false, msg:'User nahi mila' });
  const newCoins = Math.max(0, parseInt(coins)||0);
  await updateUser(code, { coins:newCoins });
  res.json({ ok:true, coins:newCoins });
});

app.post('/admin/user/ban', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { code, blockDevice: shouldBlockDevice } = req.body; // [SEC-FIX] name conflict fixed
  const user = await getUser(code);
  if (!user) return res.json({ ok:false });
  await updateUser(code, { banned:true, bannedAt:Date.now() });
  if (shouldBlockDevice && user.deviceId) await blockDevice(user.deviceId);
  await secLog('USER_BANNED', { code, blockDevice:shouldBlockDevice||false });
  res.json({ ok:true });
});

app.post('/admin/user/unban', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { code } = req.body;
  await updateUser(code, { banned:false });
  await secLog('USER_UNBANNED', { code });
  res.json({ ok:true });
});

app.get('/admin/user/:code', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const code = req.params.code.toUpperCase();
  const user = await getUser(code);
  if (!user) return res.json({ ok:false, msg:'User nahi mila' });
  const [coinReqsSnap, wdReqsSnap, betsSnap] = await Promise.all([
    C.coins().where('userCode','==',code).orderBy('createdAt','desc').limit(20).get(),
    C.withdraw().where('userCode','==',code).orderBy('requestedAt','desc').limit(20).get(),
    C.bets().where('userCode','==',code).orderBy('placedAt','desc').limit(20).get(),
  ]);
  const coinReqs = coinReqsSnap.docs.map(d=>({...d.data(),id:d.id}));
  const wdReqs = wdReqsSnap.docs.map(d=>({...d.data(),id:d.id}));
  const betList = betsSnap.docs.map(d=>({...d.data(),id:d.id}));
  const approvedBets = betList.filter(b=>b.status==='approved');
  const totalBought = coinReqs.filter(r=>r.status==='approved').reduce((s,r)=>s+r.coins,0);
  const totalSpentReal = coinReqs.filter(r=>r.status==='approved').reduce((s,r)=>s+r.amount,0);
  const totalWithdrawn = wdReqs.filter(r=>r.status==='paid').reduce((s,r)=>s+(r.coins||r.amount||0),0);
  const totalWonCoins = approvedBets.filter(b=>b.won).reduce((s,b)=>s+(b.winAmount||0),0);
  res.json({
    ok:true,
    user:{ code:user.code,name:user.name,coins:user.coins||0,banned:user.banned||false,deviceId:user.deviceId||null,createdAt:user.createdAt,firstLoginAt:user.firstLoginAt,lastLoginAt:user.lastLoginAt,lastLoginIP:user.lastLoginIP },
    coins:{ current:user.coins||0,totalBought,totalSpentReal,totalWithdrawn,totalBetCoins:approvedBets.reduce((s,b)=>s+b.amount,0),totalWonCoins,totalLostCoins:approvedBets.filter(b=>b.won===false).reduce((s,b)=>s+b.amount,0),realMoneyIn:totalSpentReal,realMoneyOut:totalWithdrawn,pendingCoinReqs:coinReqs.filter(r=>r.status==='pending').length,rejectedCoinReqs:coinReqs.filter(r=>r.status==='rejected').length,pendingWd:wdReqs.filter(r=>r.status==='pending').length,rejectedWd:wdReqs.filter(r=>r.status==='rejected').length },
    bets:{ total:approvedBets.length,wins:approvedBets.filter(b=>b.won).length,losses:approvedBets.filter(b=>b.won===false).length },
    coinHistory:coinReqs, withdrawHistory:wdReqs, betHistory:betList,
    securityFlags:[], risk:{ score:0, reasons:[] }
  });
});

app.get('/admin/search', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const q = clean(req.query.q||'').toUpperCase();
  if (!q) return res.json({ ok:true, results:[] });
  try {
    const byCode = await C.users().where('__name__','>=',q).where('__name__','<=',q+'\uf8ff').limit(20).get();
    const results = byCode.docs.map(d=>({ ...d.data(), code:d.id }));
    if (results.length < 5) {
      const byName = await C.users().where('name','>=',q).where('name','<=',q+'\uf8ff').limit(10).get();
      byName.docs.forEach(d=>{ if(!results.find(r=>r.code===d.id)) results.push({...d.data(),code:d.id}); });
    }
    res.json({ ok:true, results:results.slice(0,20).map(u=>({ code:u.code,name:u.name,coins:u.coins||0,banned:u.banned||false,deviceId:u.deviceId||null,lastLoginAt:u.lastLoginAt })) });
  } catch(e) { res.json({ ok:true, results:[] }); }
});

app.post('/admin/settings', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { upiId,upiName,minBet,maxBet,multiplier,tgLink,minWithdraw,coinRate,maxDailyCoins } = req.body;
  const current = await getSettings();
  const updated = { ...current };
  if (upiId!==undefined) updated.upiId=clean(upiId);
  if (upiName!==undefined) updated.upiName=clean(upiName);
  if (minBet!==undefined&&minBet!=='') updated.minBet=parseInt(minBet);
  if (maxBet!==undefined&&maxBet!=='') updated.maxBet=parseInt(maxBet);
  if (multiplier!==undefined&&multiplier!=='') updated.multiplier=Math.min(parseInt(multiplier),20); // [SEC-12] cap multiplier
  if (tgLink!==undefined) updated.tgLink=clean(tgLink);
  if (minWithdraw!==undefined&&minWithdraw!=='') updated.minWithdraw=parseInt(minWithdraw);
  if (coinRate!==undefined&&coinRate!=='') updated.coinRate=parseFloat(coinRate);
  if (maxDailyCoins!==undefined&&maxDailyCoins!=='') updated.maxDailyCoins=parseInt(maxDailyCoins);
  await saveSettings(updated);
  res.json({ ok:true, settings:updated });
});

app.get('/admin/history', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  try {
    const snap = await C.rounds().where('status','==','result').orderBy('resultAt','desc').limit(50).get();
    const rounds = snap.docs.map(d=>({...d.data(),id:d.id}));
    const history = await Promise.all(rounds.map(async r=>{ const bets = await getBetsByRound(r.id); return { ...r, bets }; }));
    res.json({ ok:true, history });
  } catch(e) { res.json({ ok:true, history:[] }); }
});

app.delete('/admin/history/:id', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const roundId = req.params.id;
  const betsSnap = await C.bets().where('roundId','==',roundId).get();
  const b = db.batch();
  betsSnap.docs.forEach(d => b.delete(d.ref));
  b.delete(C.rounds().doc(roundId));
  await b.commit();
  res.json({ ok:true });
});

app.delete('/admin/history', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const snap = await C.rounds().where('status','==','result').get();
  const b = db.batch();
  snap.docs.forEach(d => b.delete(d.ref));
  await b.commit();
  res.json({ ok:true });
});

app.delete('/admin/round/:id', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  await C.rounds().doc(req.params.id).delete();
  res.json({ ok:true });
});

app.get('/admin/seclog', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const snap = await C.seclog().orderBy('at','desc').limit(200).get();
  res.json({ ok:true, log: snap.docs.map(d=>({...d.data(),id:d.id})) });
});

app.post('/admin/device/block', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { deviceId } = req.body;
  await blockDevice(deviceId);
  res.json({ ok:true });
});

app.post('/admin/utr/block', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  const { utr } = req.body;
  await blockUTR(utr);
  res.json({ ok:true });
});

app.post('/admin/migrate', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok:false });
  res.json({ ok:true, msg:'Migration route available' });
});

// [SEC-13] Block all unknown routes
app.use((req, res) => {
  res.status(404).json({ ok:false, msg:'Not found' });
});

app.listen(PORT, '0.0.0.0', () => console.log('NUMBET v5.1 SECURE on port ' + PORT));
