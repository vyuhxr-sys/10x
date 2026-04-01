const express = require('express');
const cors = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'ADMIN2026';

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

// ─── FIREBASE INIT ────────────────────────────────────────
initializeApp({
  credential: cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  })
});
const db = getFirestore();
const DOC = db.collection('numbet').doc('data');

// ─── DEFAULT DATA SHAPE ───────────────────────────────────
function defaultData() {
  return {
    users: [], rounds: [], currentRoundId: null,
    withdrawRequests: [], coinRequests: [],
    blockedDevices: [], blockedUTRs: [],
    securityLog: [],
    settings: {
      upiId: '', upiName: 'Admin', minBet: 10, maxBet: 5000,
      multiplier: 9, tgLink: 'https://t.me/Winx1010',
      minWithdraw: 300, coinRate: 1, maxDailyCoins: 50000
    }
  };
}

// ─── DB HELPERS ───────────────────────────────────────────
async function load() {
  try {
    const snap = await DOC.get();
    if (snap.exists) {
      const d = snap.data();
      ensureArrays(d);
      return d;
    }
  } catch(e) { console.error('load error:', e.message); }
  return defaultData();
}

async function save(d) {
  try {
    if (d.securityLog && d.securityLog.length > 200) {
      d.securityLog = d.securityLog.slice(0, 200);
    }
    // Keep only last 100 rounds to avoid Firestore 1MB limit
    if (d.rounds && d.rounds.length > 100) {
      const current = d.currentRoundId ? d.rounds.find(r => r.id === d.currentRoundId) : null;
      const done = d.rounds.filter(r => r.id !== d.currentRoundId).slice(-99);
      d.rounds = current ? [...done, current] : done;
    }
    await DOC.set(d);
  } catch(e) { console.error('save error:', e.message); }
}

function ensureArrays(d) {
  if (!d.withdrawRequests) d.withdrawRequests = [];
  if (!d.coinRequests) d.coinRequests = [];
  if (!d.blockedDevices) d.blockedDevices = [];
  if (!d.blockedUTRs) d.blockedUTRs = [];
  if (!d.securityLog) d.securityLog = [];
  if (!d.settings) d.settings = defaultData().settings;
  if (d.settings.minWithdraw === undefined) d.settings.minWithdraw = 300;
  if (d.settings.coinRate === undefined) d.settings.coinRate = 1;
  if (d.settings.maxDailyCoins === undefined) d.settings.maxDailyCoins = 50000;
  if (!d.users) d.users = [];
  if (!d.rounds) d.rounds = [];
}

function auth(req) { return req.headers['x-pass'] === ADMIN_PASS; }
function uid() { return Date.now().toString(36) + Math.random().toString(36).substr(2,5).toUpperCase(); }
function genCode() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 8; i++) { if (i === 4) s += '-'; s += c[Math.floor(Math.random()*c.length)]; }
  return s;
}
function getCurrentRound(d) {
  if (!d.currentRoundId) return null;
  return d.rounds.find(r => r.id === d.currentRoundId) || null;
}
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}
function secLog(d, type, data) {
  if (!d.securityLog) d.securityLog = [];
  d.securityLog.unshift({ type, data, at: Date.now() });
}

// ─── RATE LIMITING ────────────────────────────────────────
const rateLimiter = {};
function checkRate(key, limit, windowMs) {
  const now = Date.now();
  if (!rateLimiter[key]) rateLimiter[key] = [];
  rateLimiter[key] = rateLimiter[key].filter(t => now - t < windowMs);
  if (rateLimiter[key].length >= limit) return false;
  rateLimiter[key].push(now);
  return true;
}

// ─── AUTO-CLOSE BETTING AT 40 MIN ─────────────────────────
setInterval(async () => {
  try {
    const d = await load();
    const round = getCurrentRound(d);
    if (!round || round.status !== 'open') return;
    if (Date.now() >= round.startedAt + 40*60*1000) {
      round.status = 'closed'; round.closedAt = Date.now();
      await save(d);
      console.log('Auto-closed round', round.id);
    }
  } catch(e) {}
}, 15000);

// ─── HEALTH CHECK ─────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'NUMBET OK', db: 'Firebase' }));

// ─── LOGIN ────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { code, deviceId } = req.body;
  const ip = getIP(req);
  if (!code) return res.json({ ok: false, msg: 'Code daalo' });
  const d = await load();

  if (!checkRate('login:'+ip, 10, 60000)) {
    secLog(d, 'RATE_LIMIT', { ip, code: code.toUpperCase(), action: 'login' });
    await save(d);
    return res.json({ ok: false, msg: 'Bahut zyada attempts. 1 minute baad try karo.' });
  }

  const user = d.users.find(u => u.code === code.trim().toUpperCase());
  if (!user) {
    secLog(d, 'LOGIN_FAIL', { ip, code: code.trim().toUpperCase() });
    await save(d);
    return res.json({ ok: false, msg: 'Galat code — Telegram se lo: @Winx1010' });
  }

  if (deviceId && (d.blockedDevices||[]).includes(deviceId)) {
    secLog(d, 'BLOCKED_DEVICE_LOGIN', { ip, code: user.code, deviceId });
    await save(d);
    return res.json({ ok: false, msg: 'Yeh device block hai. Admin se contact karo.' });
  }

  if (user.banned) {
    secLog(d, 'BANNED_USER_LOGIN', { ip, code: user.code });
    await save(d);
    return res.json({ ok: false, msg: 'Aapka account block hai. Admin se contact karo.' });
  }

  if (!user.deviceId && deviceId) {
    user.deviceId = deviceId;
    user.firstLoginAt = user.firstLoginAt || Date.now();
  } else if (user.deviceId && deviceId && user.deviceId !== deviceId) {
    secLog(d, 'DEVICE_MISMATCH', { ip, code: user.code, oldDevice: user.deviceId, newDevice: deviceId });
    await save(d);
    return res.json({ ok: false, msg: 'Yeh code doosre phone pe use ho chuka hai. Admin se contact karo.' });
  }
  user.lastLoginAt = Date.now();
  user.lastLoginIP = ip;
  if (user.coins === undefined) user.coins = 0;
  await save(d);
  return res.json({ ok: true, user: { code: user.code, name: user.name, coins: user.coins||0 }, settings: d.settings });
});

// ─── VERIFY (auto-login) ──────────────────────────────────
app.post('/verify', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = await load();
  const user = d.users.find(u => u.code === code.trim().toUpperCase());
  if (!user || user.banned) return res.json({ ok: false, msg: 'Session expire — dobara login karo' });
  if (user.coins === undefined) { user.coins = 0; await save(d); }
  return res.json({ ok: true, user: { code: user.code, name: user.name, coins: user.coins||0 }, settings: d.settings });
});

// ─── ROUND INFO ───────────────────────────────────────────
app.get('/round', async (req, res) => {
  const d = await load();
  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: true, round: null, settings: d.settings });
  const info = {
    id: round.id, status: round.status, startedAt: round.startedAt,
    betEndsAt: round.startedAt+40*60*1000, roundEndsAt: round.startedAt+60*60*1000,
    winNum: round.status==='result' ? round.winNum : null
  };
  return res.json({ ok: true, round: info, settings: d.settings });
});

// ─── MY BET STATUS (includes coins for user app) ──────────
app.post('/mybetStatus', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = await load();
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  const coins = user ? (user.coins||0) : 0;

  const currentRound = getCurrentRound(d);
  let round = currentRound;
  let bet = currentRound ? (currentRound.bets||[]).find(b => b.userCode === cleanCode) : null;

  if (!bet && !currentRound) {
    const done = d.rounds.filter(r => r.status === 'result');
    const lastResult = done.length ? done[done.length-1] : null;
    if (lastResult) {
      bet = (lastResult.bets||[]).find(b => b.userCode === cleanCode);
      round = lastResult;
    }
  }

  if (!round && !currentRound) return res.json({ ok: true, bet: null, round: null, settings: d.settings, coins });
  const activeRound = currentRound || round;
  const ri = {
    id: activeRound.id, status: activeRound.status, startedAt: activeRound.startedAt,
    betEndsAt: activeRound.startedAt+40*60*1000, roundEndsAt: activeRound.startedAt+60*60*1000,
    winNum: activeRound.status==='result' ? activeRound.winNum : null
  };
  const betInCurrentRound = bet && round && activeRound && round.id === activeRound.id;
  return res.json({ ok: true, bet: betInCurrentRound ? bet : null, round: ri, settings: d.settings, coins });
});

// ─── MY HISTORY ───────────────────────────────────────────
app.post('/myhistory', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = await load();
  const cleanCode = code.trim().toUpperCase();
  const history = d.rounds
    .filter(r => r.status === 'result')
    .map(r => {
      const bet = (r.bets||[]).find(b => b.userCode === cleanCode);
      if (!bet || bet.status === 'rejected') return null;
      return { roundId:r.id, resultAt:r.resultAt, winNum:r.winNum, myNumber:bet.number, myAmount:bet.amount, won:bet.won, winAmount:bet.winAmount||0, status:bet.status };
    })
    .filter(Boolean).reverse().slice(0, 50);
  return res.json({ ok: true, history });
});

// ─── PLACE BET ────────────────────────────────────────────
app.post('/bet', async (req, res) => {
  const { code, number, amount, utr, userUpi } = req.body;
  const ip = getIP(req);
  if (!code||number===undefined||!amount||!utr||!userUpi)
    return res.json({ ok: false, msg: 'Saari details daalo' });

  if (!checkRate('bet:'+ip, 5, 60000))
    return res.json({ ok: false, msg: 'Bahut zyada attempts. Thodi der baad try karo.' });

  const d = await load();
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user) return res.json({ ok: false, msg: 'Invalid code' });

  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: false, msg: 'Koi round nahi chala abhi' });
  if (round.status !== 'open') return res.json({ ok: false, msg: 'Betting band ho gayi' });

  const num = parseInt(number);
  if (isNaN(num)||num<0||num>9) return res.json({ ok: false, msg: 'Number 0-9 ke beech hona chahiye' });

  const amt = parseInt(amount);
  if (isNaN(amt)||amt<d.settings.minBet||amt>d.settings.maxBet)
    return res.json({ ok: false, msg: `Amount ₹${d.settings.minBet}-${d.settings.maxBet} ke beech hona chahiye` });

  const cleanUTR = utr.toString().trim().replace(/\s/g,'');
  if (!/^\d{6,20}$/.test(cleanUTR)) return res.json({ ok: false, msg: 'UTR sirf numbers hona chahiye (6-20 digit)' });

  const cleanUpi = userUpi.toString().trim();
  if (!cleanUpi) return res.json({ ok: false, msg: 'Apni UPI ID daalo' });

  const allBets = d.rounds.flatMap(r => r.bets||[]);
  if (allBets.find(b => b.utr === cleanUTR))
    return res.json({ ok: false, msg: 'Yeh UTR pehle use ho chuka hai' });

  if (d.blockedUTRs && d.blockedUTRs.includes(cleanUTR)) {
    secLog(d, 'BLOCKED_UTR', { ip, code: cleanCode, utr: cleanUTR });
    await save(d);
    return res.json({ ok: false, msg: 'Yeh UTR block hai. Admin se contact karo.' });
  }

  const existing = (round.bets||[]).find(b => b.userCode===cleanCode && b.status!=='rejected');
  if (existing) return res.json({ ok: false, msg: 'Aapki bet pehle se hai is round mein' });

  if (!round.bets) round.bets = [];
  const bet = {
    id: uid(), userCode: cleanCode, userName: user.name,
    number: num, amount: amt, utr: cleanUTR, userUpi: cleanUpi,
    status: 'pending', placedAt: Date.now(), won: null, winAmount: null, paid: false
  };
  round.bets.push(bet);
  await save(d);
  return res.json({ ok: true, bet: { id: bet.id, number: num, amount: amt, status: 'pending' } });
});

// ─── WITHDRAW REQUEST ─────────────────────────────────────
app.post('/withdraw', async (req, res) => {
  const { code, amount, upi } = req.body;
  if (!code||!amount||!upi) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = await load();
  const user = d.users.find(u => u.code === code.trim().toUpperCase());
  if (!user) return res.json({ ok: false, msg: 'Invalid code' });
  const amt = parseInt(amount);
  if (isNaN(amt)||amt<d.settings.minWithdraw) return res.json({ ok: false, msg: `Min withdraw ₹${d.settings.minWithdraw}` });
  const pending = d.withdrawRequests.filter(w => w.userCode===user.code && w.status==='pending');
  if (pending.length >= 1) return res.json({ ok: false, msg: 'Aapki ek request already pending hai' });
  d.withdrawRequests.push({ id: uid(), userCode: user.code, userName: user.name, amount: amt, upi: upi.trim(), status: 'pending', requestedAt: Date.now() });
  await save(d);
  return res.json({ ok: true });
});

// ─── COIN BUY REQUEST ─────────────────────────────────────
app.post('/coins/buy', async (req, res) => {
  const { code, amount, utr } = req.body;
  if (!code||!amount||!utr) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = await load();
  const user = d.users.find(u => u.code === code.trim().toUpperCase());
  if (!user) return res.json({ ok: false, msg: 'Invalid code' });
  const amt = parseInt(amount);
  if (isNaN(amt)||amt<10) return res.json({ ok: false, msg: 'Min ₹10 se coins lo' });
  const cleanUTR = utr.toString().trim().replace(/\s/g,'');
  const allReqs = d.coinRequests||[];
  if (allReqs.find(r => r.utr === cleanUTR)) return res.json({ ok: false, msg: 'Yeh UTR pehle use ho chuka hai' });
  const coins = Math.floor(amt * (d.settings.coinRate||1));
  d.coinRequests.push({ id: uid(), userCode: user.code, userName: user.name, amount: amt, utr: cleanUTR, coins, status: 'pending', requestedAt: Date.now(), createdAt: Date.now() });
  await save(d);
  return res.json({ ok: true, coinsWillGet: coins });
});

// ─── ADMIN DATA ───────────────────────────────────────────
app.get('/admin/data', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load();
  const round = getCurrentRound(d);
  let numStats = null;
  if (round && round.bets) {
    numStats = {};
    for (let i=0;i<=9;i++) numStats[i]={count:0,total:0,bets:[]};
    round.bets.filter(b=>b.status==='approved').forEach(b=>{
      numStats[b.number].count++;
      numStats[b.number].total+=b.amount;
      numStats[b.number].bets.push({name:b.userName,code:b.userCode,amount:b.amount});
    });
  }
  const ri = round ? { ...round, betEndsAt:round.startedAt+40*60*1000, roundEndsAt:round.startedAt+60*60*1000 } : null;
  const pendingCoins = (d.coinRequests||[]).filter(c=>c.status==='pending').length;
  const pendingWithdraw = (d.withdrawRequests||[]).filter(w=>w.status==='pending').length;
  return res.json({
    ok: true, users: d.users, round: ri, numStats, settings: d.settings,
    pendingCoins, pendingWithdraw,
    stats: {
      totalUsers: d.users.length,
      totalRounds: d.rounds.filter(r=>r.status==='result').length,
      currentBets: round?(round.bets||[]).filter(b=>b.status==='approved').length:0,
      currentAmount: round?(round.bets||[]).filter(b=>b.status==='approved').reduce((s,b)=>s+b.amount,0):0,
    }
  });
});

// ─── ROUND CONTROLS ───────────────────────────────────────
app.post('/admin/round/start', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load();
  if (getCurrentRound(d)) return res.json({ ok: false, msg: 'Pehle current round finish karo' });
  const round = { id: uid(), status: 'open', startedAt: Date.now(), closedAt: null, resultAt: null, winNum: null, bets: [] };
  d.rounds.push(round); d.currentRoundId = round.id;
  await save(d);
  res.json({ ok: true, round });
});

app.post('/admin/round/close', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load(); const round = getCurrentRound(d);
  if (!round||round.status!=='open') return res.json({ ok: false, msg: 'Koi open round nahi' });
  round.status='closed'; round.closedAt=Date.now();
  await save(d); res.json({ ok: true });
});

app.post('/admin/round/result', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { winNum } = req.body; const num = parseInt(winNum);
  if (isNaN(num)||num<0||num>9) return res.json({ ok: false, msg: '0-9 mein se number daalo' });
  const d = await load(); const round = getCurrentRound(d);
  if (!round||round.status==='result') return res.json({ ok: false, msg: 'Round result ke liye ready nahi' });
  const mult = d.settings.multiplier||9;
  round.status='result'; round.winNum=num; round.resultAt=Date.now();
  const winners=[];
  (round.bets||[]).forEach(b=>{
    if(b.status==='approved'){
      b.won=b.number===num;
      b.winAmount=b.won?b.amount*mult:0;
      if(b.won){
        // Auto-credit coins to winner
        const user = d.users.find(u=>u.code===b.userCode);
        if(user){ user.coins=(user.coins||0)+b.winAmount; }
        winners.push({name:b.userName,code:b.userCode,coins:b.winAmount});
      }
    }
  });
  d.currentRoundId=null;
  await save(d);
  res.json({ ok: true, winNum: num, winners });
});

// ─── BET VERIFY / PAID ────────────────────────────────────
app.post('/admin/bet/verify', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { betId, action } = req.body; const d = await load();
  for (const round of d.rounds) {
    const bet = (round.bets||[]).find(b=>b.id===betId);
    if (bet) { bet.status=action==='approve'?'approved':'rejected'; bet.verifiedAt=Date.now(); await save(d); return res.json({ ok:true, status:bet.status }); }
  }
  res.json({ ok: false, msg: 'Bet nahi mili' });
});

app.post('/admin/bet/paid', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { betId } = req.body; const d = await load();
  for (const round of d.rounds) {
    const bet = (round.bets||[]).find(b=>b.id===betId);
    if (bet) { bet.paid=true; bet.paidAt=Date.now(); await save(d); return res.json({ ok:true }); }
  }
  res.json({ ok: false });
});

// ─── COIN REQUESTS (admin) ────────────────────────────────
// GET all coin requests
app.get('/admin/coins', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load();
  res.json({ ok: true, requests: (d.coinRequests||[]).slice().reverse() });
});

// Approve coin request
app.post('/admin/coins/approve', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body; const d = await load();
  const cr = (d.coinRequests||[]).find(c=>c.id===reqId);
  if (!cr) return res.json({ ok: false, msg: 'Request nahi mili' });
  if (cr.status !== 'pending') return res.json({ ok: false, msg: 'Already processed' });
  cr.status='approved'; cr.actionAt=Date.now();
  const user = d.users.find(u=>u.code===cr.userCode);
  if (user) user.coins=(user.coins||0)+cr.coins;
  await save(d);
  res.json({ ok: true });
});

// Reject coin request (with optional UTR block)
app.post('/admin/coins/reject', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId, blockUTR } = req.body; const d = await load();
  const cr = (d.coinRequests||[]).find(c=>c.id===reqId);
  if (!cr) return res.json({ ok: false, msg: 'Request nahi mili' });
  cr.status='rejected'; cr.actionAt=Date.now();
  if (blockUTR && cr.utr) {
    if (!d.blockedUTRs) d.blockedUTRs=[];
    if (!d.blockedUTRs.includes(cr.utr)) d.blockedUTRs.push(cr.utr);
  }
  await save(d);
  res.json({ ok: true });
});

// Old combined action (keep for compatibility)
app.post('/admin/coins/action', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { id, action } = req.body; const d = await load();
  const cr = (d.coinRequests||[]).find(c=>c.id===id);
  if (!cr) return res.json({ ok: false, msg: 'Request nahi mili' });
  cr.status=action==='approve'?'approved':'rejected'; cr.actionAt=Date.now();
  if (action==='approve') {
    const user = d.users.find(u=>u.code===cr.userCode);
    if (user) user.coins=(user.coins||0)+cr.coins;
  }
  await save(d); res.json({ ok: true });
});

// ─── WITHDRAW REQUESTS (admin) ────────────────────────────
// GET all withdraw requests
app.get('/admin/withdraw', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load();
  res.json({ ok: true, requests: (d.withdrawRequests||[]).slice().reverse() });
});

// Mark withdraw as paid
app.post('/admin/withdraw/done', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body; const d = await load();
  const wr = (d.withdrawRequests||[]).find(w=>w.id===reqId);
  if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
  wr.status='paid'; wr.paidAt=Date.now();
  await save(d); res.json({ ok: true });
});

// Reject withdraw (refund coins)
app.post('/admin/withdraw/reject', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body; const d = await load();
  const wr = (d.withdrawRequests||[]).find(w=>w.id===reqId);
  if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
  wr.status='rejected'; wr.processedAt=Date.now();
  // Refund coins if applicable
  if (wr.coins) {
    const user = d.users.find(u=>u.code===wr.userCode);
    if (user) user.coins=(user.coins||0)+wr.coins;
  }
  await save(d); res.json({ ok: true });
});

// Old combined action (keep for compatibility)
app.post('/admin/withdraw/action', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { id, action } = req.body; const d = await load();
  const wr = (d.withdrawRequests||[]).find(w=>w.id===id);
  if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
  wr.status=action==='approve'?'approved':'rejected'; wr.actionAt=Date.now();
  await save(d); res.json({ ok: true });
});

// ─── USER MANAGEMENT ──────────────────────────────────────
app.post('/admin/user', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { name } = req.body; const d = await load(); const code = genCode();
  d.users.push({ code, name:name||'User', createdAt:Date.now(), deviceId:null, coins:0, banned:false });
  await save(d);
  res.json({ ok:true, code, name:name||'User' });
});

app.delete('/admin/user/:code', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load();
  d.users = d.users.filter(u=>u.code!==req.params.code);
  await save(d); res.json({ ok: true });
});

app.post('/admin/user/resetdevice', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code } = req.body; const d = await load();
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  user.deviceId=null; await save(d); res.json({ ok: true });
});

// Adjust coins manually
app.post('/admin/user/coins', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code, coins } = req.body; const d = await load();
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  user.coins = Math.max(0, parseInt(coins)||0);
  await save(d); res.json({ ok: true, coins: user.coins });
});

// Ban user (with optional device block)
app.post('/admin/user/ban', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code, blockDevice } = req.body; const d = await load();
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false });
  user.banned = true; user.bannedAt = Date.now();
  if (blockDevice && user.deviceId) {
    if (!d.blockedDevices) d.blockedDevices=[];
    if (!d.blockedDevices.includes(user.deviceId)) d.blockedDevices.push(user.deviceId);
  }
  secLog(d, 'USER_BANNED', { code, blockDevice: blockDevice||false });
  await save(d); res.json({ ok: true });
});

// Unban user
app.post('/admin/user/unban', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code } = req.body; const d = await load();
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false });
  user.banned = false; delete user.bannedAt;
  secLog(d, 'USER_UNBANNED', { code });
  await save(d); res.json({ ok: true });
});

// User profile (full detail for admin)
app.get('/admin/user/:code', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load();
  const code = req.params.code.toUpperCase();
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });

  const coinReqs = (d.coinRequests||[]).filter(r=>r.userCode===code);
  const wdReqs = (d.withdrawRequests||[]).filter(r=>r.userCode===code);
  const allBets = d.rounds.flatMap(r => {
    const bet=(r.bets||[]).find(b=>b.userCode===code);
    if(!bet) return [];
    return [{ ...bet, roundWinNum:r.winNum, resultAt:r.resultAt, roundId:r.id }];
  });
  const approvedBets = allBets.filter(b=>b.status==='approved');
  const totalBought = coinReqs.filter(r=>r.status==='approved').reduce((s,r)=>s+r.coins,0);
  const totalSpentReal = coinReqs.filter(r=>r.status==='approved').reduce((s,r)=>s+r.amount,0);
  const totalWithdrawn = wdReqs.filter(r=>r.status==='paid').reduce((s,r)=>s+(r.coins||r.amount||0),0);
  const totalWonCoins = approvedBets.filter(b=>b.won).reduce((s,b)=>s+(b.winAmount||0),0);
  const totalLostCoins = approvedBets.filter(b=>b.won===false).reduce((s,b)=>s+b.amount,0);

  // Risk score
  let riskScore=0; const riskReasons=[];
  const rejCR = coinReqs.filter(r=>r.status==='rejected').length;
  if(rejCR>2){riskScore+=30;riskReasons.push('Multiple rejected coin requests');}
  const secFlags = (d.securityLog||[]).filter(l=>l.data&&l.data.code===code&&['DUPLICATE_UTR','BLOCKED_UTR','DEVICE_MISMATCH','WITHDRAW_FRAUD_ATTEMPT'].includes(l.type));
  if(secFlags.length>0){riskScore+=secFlags.length*25;riskReasons.push(secFlags.length+' security flags');}

  res.json({
    ok: true,
    user: { code:user.code,name:user.name,coins:user.coins||0,banned:user.banned||false,deviceId:user.deviceId||null,createdAt:user.createdAt,firstLoginAt:user.firstLoginAt,lastLoginAt:user.lastLoginAt,lastLoginIP:user.lastLoginIP },
    coins: { current:user.coins||0,totalBought,totalSpentReal,totalWithdrawn,totalBetCoins:approvedBets.reduce((s,b)=>s+b.amount,0),totalWonCoins,totalLostCoins,realMoneyIn:totalSpentReal,realMoneyOut:totalWithdrawn,pendingCoinReqs:coinReqs.filter(r=>r.status==='pending').length,rejectedCoinReqs:rejCR,pendingWd:wdReqs.filter(r=>r.status==='pending').length,rejectedWd:wdReqs.filter(r=>r.status==='rejected').length },
    bets: { total:approvedBets.length,wins:approvedBets.filter(b=>b.won).length,losses:approvedBets.filter(b=>b.won===false).length },
    coinHistory: coinReqs.slice().reverse().slice(0,20),
    withdrawHistory: wdReqs.slice().reverse().slice(0,20),
    betHistory: allBets.slice(-20).reverse(),
    securityFlags: secFlags,
    risk: { score:Math.min(riskScore,100),reasons:riskReasons }
  });
});

// Search users
app.get('/admin/search', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const q = (req.query.q||'').toUpperCase().trim();
  if (!q) return res.json({ ok: true, results: [] });
  const d = await load();
  const results = d.users
    .filter(u => u.code.includes(q) || (u.name||'').toUpperCase().includes(q))
    .slice(0, 20)
    .map(u => ({ code:u.code,name:u.name,coins:u.coins||0,banned:u.banned||false,deviceId:u.deviceId||null,lastLoginAt:u.lastLoginAt }));
  res.json({ ok: true, results });
});

// ─── SETTINGS ─────────────────────────────────────────────
app.post('/admin/settings', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { upiId, upiName, minBet, maxBet, multiplier, tgLink, minWithdraw, coinRate, maxDailyCoins } = req.body;
  const d = await load();
  if (upiId!==undefined) d.settings.upiId=upiId;
  if (upiName!==undefined) d.settings.upiName=upiName;
  if (minBet!==undefined&&minBet!=='') d.settings.minBet=parseInt(minBet);
  if (maxBet!==undefined&&maxBet!=='') d.settings.maxBet=parseInt(maxBet);
  if (multiplier!==undefined&&multiplier!=='') d.settings.multiplier=parseInt(multiplier);
  if (tgLink!==undefined) d.settings.tgLink=tgLink;
  if (minWithdraw!==undefined&&minWithdraw!=='') d.settings.minWithdraw=parseInt(minWithdraw);
  if (coinRate!==undefined&&coinRate!=='') d.settings.coinRate=parseFloat(coinRate);
  if (maxDailyCoins!==undefined&&maxDailyCoins!=='') d.settings.maxDailyCoins=parseInt(maxDailyCoins);
  await save(d); res.json({ ok:true, settings:d.settings });
});

// ─── HISTORY ──────────────────────────────────────────────
app.get('/admin/history', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load();
  const history = d.rounds.filter(r=>r.status==='result').slice(-50).reverse();
  res.json({ ok:true, history });
});

// Delete single round (admin.html calls /admin/history/:id)
app.delete('/admin/history/:id', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load();
  const before = d.rounds.length;
  d.rounds = d.rounds.filter(r => r.id !== req.params.id);
  if (d.rounds.length === before) return res.json({ ok:false, msg:'Round nahi mila' });
  await save(d); res.json({ ok:true });
});

// Delete ALL history
app.delete('/admin/history', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load();
  d.rounds = d.rounds.filter(r => r.status !== 'result');
  await save(d); res.json({ ok:true });
});

// Old route (keep for compatibility)
app.delete('/admin/round/:id', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load();
  d.rounds = d.rounds.filter(r => r.id !== req.params.id);
  await save(d); res.json({ ok:true });
});

// ─── SECURITY LOG ─────────────────────────────────────────
app.get('/admin/seclog', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = await load();
  res.json({ ok: true, log: (d.securityLog||[]).slice(0,200) });
});

// ─── DEVICE / UTR BLOCK ───────────────────────────────────
app.post('/admin/device/block', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { deviceId } = req.body; const d = await load();
  if (!d.blockedDevices) d.blockedDevices=[];
  if (!d.blockedDevices.includes(deviceId)) d.blockedDevices.push(deviceId);
  await save(d); res.json({ ok: true });
});

app.post('/admin/utr/block', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { utr } = req.body; const d = await load();
  if (!d.blockedUTRs) d.blockedUTRs=[];
  if (!d.blockedUTRs.includes(utr)) d.blockedUTRs.push(utr);
  await save(d); res.json({ ok: true });
});

app.listen(PORT, '0.0.0.0', () => console.log('NUMBET Firebase server on ' + PORT));
