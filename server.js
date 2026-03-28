const express = require('express');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'ADMIN2026';
const DATA = './db.json';
const LOG = './security.log';

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50kb' })); // limit body size

// ════════════════════════════════════════════════════════
// SECURITY: Rate Limiter (in-memory, per IP)
// ════════════════════════════════════════════════════════
const rateLimits = {};
function rateLimit(ip, key, maxReq, windowMs) {
  const k = ip + ':' + key;
  const now = Date.now();
  if (!rateLimits[k]) rateLimits[k] = { count: 0, start: now };
  if (now - rateLimits[k].start > windowMs) { rateLimits[k] = { count: 1, start: now }; return false; }
  rateLimits[k].count++;
  return rateLimits[k].count > maxReq;
}
// Clean rate limit memory every 10 min
setInterval(() => { const now = Date.now(); Object.keys(rateLimits).forEach(k => { if (now - rateLimits[k].start > 600000) delete rateLimits[k]; }); }, 600000);

function getIP(req) { return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.connection?.remoteAddress || 'unknown'; }

// ════════════════════════════════════════════════════════
// SECURITY LOG
// ════════════════════════════════════════════════════════
function secLog(type, data) {
  const entry = JSON.stringify({ t: new Date().toISOString(), type, ...data }) + '\n';
  try { fs.appendFileSync(LOG, entry); } catch(e) {}
  console.log('[SEC]', type, data);
}

// ════════════════════════════════════════════════════════
// DB
// ════════════════════════════════════════════════════════
const DB_LOCK = { writing: false };
function load() {
  try { if (fs.existsSync(DATA)) return JSON.parse(fs.readFileSync(DATA, 'utf8')); } catch(e) {}
  return {
    users: [], rounds: [], currentRoundId: null,
    withdrawRequests: [], coinRequests: [],
    blockedUTRs: [],   // permanent UTR blacklist
    blockedIPs: [],    // blocked IPs
    settings: {
      upiId: '', upiName: 'Admin', minBet: 10, maxBet: 5000,
      multiplier: 9, tgLink: 'https://t.me/Winx1010',
      minWithdraw: 300, coinRate: 1,
      maxCoinBuyPerDay: 10000,   // max coins per user per day
      maxWithdrawPerDay: 5000    // max withdraw per day per user
    }
  };
}
function save(d) {
  if (DB_LOCK.writing) { setTimeout(() => save(d), 50); return; }
  DB_LOCK.writing = true;
  try {
    const tmp = DATA + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(d, null, 2));
    fs.renameSync(tmp, DATA); // atomic write
  } catch(e) { console.error('Save error', e); }
  finally { DB_LOCK.writing = false; }
}
function ensureDB(d) {
  if (!d.withdrawRequests) d.withdrawRequests = [];
  if (!d.coinRequests) d.coinRequests = [];
  if (!d.blockedUTRs) d.blockedUTRs = [];
  if (!d.blockedIPs) d.blockedIPs = [];
  if (!d.settings.minWithdraw) d.settings.minWithdraw = 300;
  if (!d.settings.coinRate) d.settings.coinRate = 1;
  if (!d.settings.maxCoinBuyPerDay) d.settings.maxCoinBuyPerDay = 10000;
  if (!d.settings.maxWithdrawPerDay) d.settings.maxWithdrawPerDay = 5000;
}
function auth(req) { return req.headers['x-pass'] === ADMIN_PASS; }
function uid() { return Date.now().toString(36) + crypto.randomBytes(3).toString('hex').toUpperCase(); }
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

// ════════════════════════════════════════════════════════
// SECURITY HELPERS
// ════════════════════════════════════════════════════════
// All UTRs ever used (coin buy + old bets)
function getAllUsedUTRs(d) {
  const fromCoins = d.coinRequests.map(r => r.utr);
  return new Set(fromCoins);
}

// Check if user bought too many coins today
function getCoinsBoughtToday(d, userCode) {
  const today = new Date(); today.setHours(0,0,0,0);
  return d.coinRequests
    .filter(r => r.userCode === userCode && r.status !== 'rejected' && r.createdAt >= today.getTime())
    .reduce((s, r) => s + (r.coins || 0), 0);
}

// Check if user withdrew too much today
function getWithdrawnToday(d, userCode) {
  const today = new Date(); today.setHours(0,0,0,0);
  return d.withdrawRequests
    .filter(r => r.userCode === userCode && r.status !== 'rejected' && r.createdAt >= today.getTime())
    .reduce((s, r) => s + (r.coins || 0), 0);
}

// Suspicious pattern: same amount too many times
function hasSuspiciousPattern(d, userCode) {
  const recent = d.coinRequests.filter(r => r.userCode === userCode).slice(-10);
  if (recent.length < 3) return false;
  const amounts = recent.map(r => r.amount);
  const unique = new Set(amounts);
  // If all recent requests have same amount = suspicious
  if (unique.size === 1 && recent.length >= 5) return true;
  return false;
}

// Build user audit trail (for admin to see)
function buildUserAudit(d, userCode) {
  const coinBuys = d.coinRequests.filter(r => r.userCode === userCode);
  const withdrawals = d.withdrawRequests.filter(r => r.userCode === userCode);
  const bets = d.rounds.flatMap(r => (r.bets || []).filter(b => b.userCode === userCode));
  const totalBought = coinBuys.filter(r => r.status === 'approved').reduce((s, r) => s + r.coins, 0);
  const totalWon = bets.filter(b => b.won).reduce((s, b) => s + (b.winAmount || 0), 0);
  const totalBet = bets.filter(b => b.status === 'approved').reduce((s, b) => s + b.amount, 0);
  const totalWithdrawn = withdrawals.filter(r => r.status !== 'rejected').reduce((s, r) => s + r.coins, 0);
  return { totalBought, totalWon, totalBet, totalWithdrawn, coinBuys: coinBuys.length, withdrawals: withdrawals.length, bets: bets.length };
}

// Auto-close betting at 40 min
setInterval(() => {
  try {
    const d = load();
    const round = getCurrentRound(d);
    if (!round || round.status !== 'open') return;
    if (Date.now() >= round.startedAt + 40*60*1000) {
      round.status = 'closed'; round.closedAt = Date.now();
      save(d);
    }
  } catch(e) {}
}, 15000);

// ════════════════════════════════════════════════════════
// MIDDLEWARE: Block flagged IPs
// ════════════════════════════════════════════════════════
app.use((req, res, next) => {
  const ip = getIP(req);
  const d = load();
  if ((d.blockedIPs || []).includes(ip)) {
    secLog('BLOCKED_IP', { ip, path: req.path });
    return res.status(403).json({ ok: false, msg: 'Access denied' });
  }
  next();
});

// ════════════════════════════════════════════════════════
// PUBLIC ROUTES
// ════════════════════════════════════════════════════════

app.post('/login', (req, res) => {
  const ip = getIP(req);
  if (rateLimit(ip, 'login', 10, 60000)) {
    secLog('RATE_LIMIT_LOGIN', { ip });
    return res.json({ ok: false, msg: 'Bahut zyada attempts. 1 min ruko.' });
  }
  const { code, deviceId } = req.body;
  if (!code || typeof code !== 'string') return res.json({ ok: false, msg: 'Code daalo' });
  const d = load(); ensureDB(d);
  const cleanCode = code.trim().toUpperCase().substring(0, 20);
  const user = d.users.find(u => u.code === cleanCode);
  if (!user) {
    secLog('LOGIN_FAIL', { ip, code: cleanCode });
    return res.json({ ok: false, msg: 'Galat code — Telegram se lo: @Winx1010' });
  }
  const cleanDevice = deviceId ? String(deviceId).substring(0, 100) : null;
  if (!user.deviceId && cleanDevice) { user.deviceId = cleanDevice; save(d); }
  else if (user.deviceId && cleanDevice && user.deviceId !== cleanDevice) {
    secLog('DEVICE_MISMATCH', { ip, code: cleanCode, expected: user.deviceId, got: cleanDevice });
    return res.json({ ok: false, msg: 'Yeh code doosre phone pe use ho chuka hai. Admin se contact karo.' });
  }
  if (user.banned) return res.json({ ok: false, msg: 'Account suspended. Admin se contact karo.' });
  if (user.coins === undefined) { user.coins = 0; save(d); }
  const audit = buildUserAudit(d, cleanCode);
  return res.json({ ok: true, user: { code: user.code, name: user.name, coins: user.coins }, settings: d.settings, audit });
});

app.post('/verify', (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = load(); ensureDB(d);
  const user = d.users.find(u => u.code === code.trim().toUpperCase());
  if (!user || user.banned) return res.json({ ok: false, msg: 'Session expire — dobara login karo' });
  if (user.coins === undefined) { user.coins = 0; }
  return res.json({ ok: true, user: { code: user.code, name: user.name, coins: user.coins }, settings: d.settings });
});

app.get('/round', (req, res) => {
  const d = load();
  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: true, round: null, settings: d.settings });
  const info = { id: round.id, status: round.status, startedAt: round.startedAt,
    betEndsAt: round.startedAt+40*60*1000, roundEndsAt: round.startedAt+60*60*1000,
    winNum: round.status==='result' ? round.winNum : null };
  return res.json({ ok: true, round: info, settings: d.settings });
});

app.post('/mybetStatus', (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = load(); ensureDB(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user) return res.json({ ok: false });
  let round = getCurrentRound(d);
  if (!round) { const done = d.rounds.filter(r=>r.status==='result'); round = done.length ? done[done.length-1] : null; }
  const coins = user.coins || 0;
  if (!round) return res.json({ ok: true, bet: null, round: null, settings: d.settings, coins });
  const bet = (round.bets||[]).find(b => b.userCode === cleanCode);
  const ri = { id:round.id, status:round.status, startedAt:round.startedAt,
    betEndsAt:round.startedAt+40*60*1000, roundEndsAt:round.startedAt+60*60*1000,
    winNum:round.status==='result'?round.winNum:null };
  return res.json({ ok: true, bet: bet||null, round: ri, settings: d.settings, coins });
});

app.post('/myhistory', (req, res) => {
  const ip = getIP(req);
  if (rateLimit(ip, 'hist', 20, 60000)) return res.json({ ok: false });
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = load();
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user) return res.json({ ok: false });
  const history = d.rounds.filter(r => r.status === 'result').map(r => {
    const bet = (r.bets||[]).find(b => b.userCode === cleanCode);
    if (!bet || bet.status === 'rejected') return null;
    return { roundId: r.id, resultAt: r.resultAt, winNum: r.winNum, myNumber: bet.number, myAmount: bet.amount, won: bet.won, winAmount: bet.winAmount||0, status: bet.status };
  }).filter(Boolean).reverse().slice(0, 50);
  // Also include coin tx history
  const coinTx = d.coinRequests.filter(r => r.userCode === cleanCode).slice(-20).reverse().map(r => ({
    type: 'coin_buy', amount: r.amount, coins: r.coins, status: r.status, createdAt: r.createdAt
  }));
  const withdrawTx = d.withdrawRequests.filter(r => r.userCode === cleanCode).slice(-20).reverse().map(r => ({
    type: 'withdraw', coins: r.coins, upiId: r.upiId, status: r.status, createdAt: r.createdAt
  }));
  return res.json({ ok: true, history, coinTx, withdrawTx, coins: user.coins||0 });
});

app.post('/bet', (req, res) => {
  const ip = getIP(req);
  if (rateLimit(ip, 'bet', 5, 30000)) return res.json({ ok: false, msg: 'Bahut zyada attempts. Thoda ruko.' });
  const { code, number, amount } = req.body;
  if (!code || number === undefined || !amount) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = load(); ensureDB(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });
  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: false, msg: 'Koi round nahi chala abhi' });
  if (round.status !== 'open') return res.json({ ok: false, msg: 'Betting band ho gayi' });
  const num = parseInt(number);
  if (isNaN(num)||num<0||num>9) return res.json({ ok: false, msg: 'Number 0-9 ke beech' });
  const amt = parseInt(amount);
  if (isNaN(amt)||amt<d.settings.minBet||amt>d.settings.maxBet)
    return res.json({ ok: false, msg: `Coins ${d.settings.minBet}–${d.settings.maxBet} ke beech hona chahiye` });
  if ((user.coins||0) < amt)
    return res.json({ ok: false, msg: `Aapke paas sirf ${user.coins||0} coins hain` });
  const existing = (round.bets||[]).find(b => b.userCode===cleanCode && b.status!=='rejected');
  if (existing) return res.json({ ok: false, msg: 'Aapki bet pehle se hai' });
  user.coins = (user.coins||0) - amt;
  if (!round.bets) round.bets = [];
  const bet = { id:uid(), userCode:cleanCode, userName:user.name, number:num, amount:amt, status:'approved', placedAt:Date.now(), ip, won:null, winAmount:null };
  round.bets.push(bet);
  save(d);
  secLog('BET_PLACED', { ip, code: cleanCode, number: num, amount: amt });
  return res.json({ ok: true, bet: { id:bet.id, number:num, amount:amt, status:'approved' }, coins: user.coins });
});

// ─── COIN BUY (secure) ────────────────────────────────────
app.post('/coins/buy', (req, res) => {
  const ip = getIP(req);
  if (rateLimit(ip, 'coinbuy', 5, 300000)) { // 5 requests per 5 min
    secLog('RATE_LIMIT_COINBUY', { ip });
    return res.json({ ok: false, msg: 'Bahut zyada requests. 5 min baad try karo.' });
  }
  const { code, utr, amount } = req.body;
  if (!code||!utr||!amount) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = load(); ensureDB(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });
  const cleanUTR = String(utr).trim().replace(/\s/g,'');
  if (!/^\d{6,25}$/.test(cleanUTR)) return res.json({ ok: false, msg: 'UTR sirf numbers (6-25 digit)' });
  // Blocked UTR check
  if ((d.blockedUTRs||[]).includes(cleanUTR)) {
    secLog('BLOCKED_UTR_ATTEMPT', { ip, code: cleanCode, utr: cleanUTR });
    return res.json({ ok: false, msg: 'Yeh UTR invalid hai. Admin se contact karo.' });
  }
  // Global UTR uniqueness check
  const usedUTRs = getAllUsedUTRs(d);
  if (usedUTRs.has(cleanUTR)) {
    secLog('DUPLICATE_UTR', { ip, code: cleanCode, utr: cleanUTR });
    return res.json({ ok: false, msg: 'Yeh UTR pehle use ho chuka hai' });
  }
  const amt = parseInt(amount);
  if (isNaN(amt)||amt<10||amt>100000) return res.json({ ok: false, msg: 'Amount ₹10–₹1,00,000 ke beech hona chahiye' });
  // Daily limit check
  const boughtToday = getCoinsBoughtToday(d, cleanCode);
  const coinsToAdd = Math.floor(amt * (d.settings.coinRate||1));
  const maxPerDay = d.settings.maxCoinBuyPerDay || 10000;
  if (boughtToday + coinsToAdd > maxPerDay) {
    secLog('DAILY_LIMIT_EXCEEDED', { ip, code: cleanCode, boughtToday, requested: coinsToAdd });
    return res.json({ ok: false, msg: `Aaj ki limit ${maxPerDay} coins hai. Kal dobara karo.` });
  }
  // Suspicious pattern check
  if (hasSuspiciousPattern(d, cleanCode)) {
    secLog('SUSPICIOUS_PATTERN', { ip, code: cleanCode, utr: cleanUTR, amount: amt });
    // Flag user but don't block — admin will review
    user.suspicious = (user.suspicious || 0) + 1;
  }
  const req_obj = {
    id: uid(), userCode: cleanCode, userName: user.name, utr: cleanUTR,
    amount: amt, coins: coinsToAdd, status: 'pending', createdAt: Date.now(), ip,
    suspicious: (user.suspicious||0) > 2
  };
  d.coinRequests.push(req_obj);
  save(d);
  secLog('COIN_REQUEST', { ip, code: cleanCode, utr: cleanUTR, amount: amt, coins: coinsToAdd });
  return res.json({ ok: true, msg: 'Request bhej di! Admin verify karega jald.' });
});

// ─── WITHDRAW (secure) ────────────────────────────────────
app.post('/withdraw', (req, res) => {
  const ip = getIP(req);
  if (rateLimit(ip, 'withdraw', 3, 300000)) { // 3 per 5 min
    secLog('RATE_LIMIT_WITHDRAW', { ip });
    return res.json({ ok: false, msg: 'Bahut zyada requests. 5 min baad try karo.' });
  }
  const { code, coins, upiId } = req.body;
  if (!code||!coins||!upiId) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = load(); ensureDB(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });
  const c = parseInt(coins);
  const minW = d.settings.minWithdraw || 300;
  if (isNaN(c)||c<minW) return res.json({ ok: false, msg: `Minimum ${minW} coins withdraw kar sakte ho` });
  if ((user.coins||0) < c) return res.json({ ok: false, msg: `Aapke paas sirf ${user.coins||0} coins hain` });
  const cleanUpi = String(upiId).trim().substring(0, 100);
  if (!cleanUpi || cleanUpi.length < 5) return res.json({ ok: false, msg: 'Valid UPI ID daalo' });
  // Check if user has pending withdraw (1 at a time)
  const pendingW = d.withdrawRequests.find(r => r.userCode===cleanCode && r.status==='pending');
  if (pendingW) return res.json({ ok: false, msg: 'Ek withdraw request pehle se pending hai. Uska wait karo.' });
  // Daily withdraw limit
  const withdrawnToday = getWithdrawnToday(d, cleanCode);
  const maxWPerDay = d.settings.maxWithdrawPerDay || 5000;
  if (withdrawnToday + c > maxWPerDay) {
    return res.json({ ok: false, msg: `Aaj ki withdraw limit ${maxWPerDay} coins hai` });
  }
  // Audit check: user should have bought >= coins they're withdrawing (total)
  const audit = buildUserAudit(d, cleanCode);
  const maxLegalWithdraw = audit.totalBought + audit.totalWon;
  const alreadyWithdrawn = audit.totalWithdrawn;
  if (c + alreadyWithdrawn > maxLegalWithdraw + 100) { // 100 coins tolerance
    secLog('SUSPICIOUS_WITHDRAW', { ip, code: cleanCode, requesting: c, maxAllowed: maxLegalWithdraw - alreadyWithdrawn, audit });
    return res.json({ ok: false, msg: 'Withdraw limit exceeded. Admin se contact karo.' });
  }
  // Deduct coins first
  user.coins = (user.coins||0) - c;
  const wr = { id:uid(), userCode:cleanCode, userName:user.name, coins:c, upiId:cleanUpi, status:'pending', createdAt:Date.now(), ip, audit };
  d.withdrawRequests.push(wr);
  save(d);
  secLog('WITHDRAW_REQUEST', { ip, code: cleanCode, coins: c, upiId: cleanUpi });
  return res.json({ ok: true, msg: `${c} coins withdraw request bhej di!`, coins: user.coins });
});

// ════════════════════════════════════════════════════════
// ADMIN ROUTES
// ════════════════════════════════════════════════════════

app.get('/admin/data', (req, res) => {
  if (!auth(req)) { secLog('ADMIN_AUTH_FAIL', { ip: getIP(req) }); return res.status(401).json({ ok: false }); }
  const d = load(); ensureDB(d);
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
  const pendingCoins = d.coinRequests.filter(r=>r.status==='pending').length;
  const pendingWithdraw = d.withdrawRequests.filter(r=>r.status==='pending').length;
  const suspiciousUsers = d.users.filter(u=>(u.suspicious||0)>0).length;
  return res.json({
    ok: true, users: d.users, round: ri, numStats, settings: d.settings,
    pendingCoins, pendingWithdraw, suspiciousUsers,
    stats: {
      totalUsers: d.users.length,
      totalRounds: d.rounds.filter(r=>r.status==='result').length,
      currentBets: round ? (round.bets||[]).filter(b=>b.status==='approved').length : 0,
      currentAmount: round ? (round.bets||[]).filter(b=>b.status==='approved').reduce((s,b)=>s+b.amount,0) : 0
    }
  });
});

app.post('/admin/round/start', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  if (getCurrentRound(d)) return res.json({ ok: false, msg: 'Pehle current round finish karo' });
  const round = { id:uid(), status:'open', startedAt:Date.now(), closedAt:null, resultAt:null, winNum:null, bets:[] };
  d.rounds.push(round); d.currentRoundId = round.id; save(d);
  secLog('ROUND_START', { id: round.id });
  res.json({ ok: true, round });
});

app.post('/admin/round/close', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); const round = getCurrentRound(d);
  if (!round||round.status!=='open') return res.json({ ok: false, msg: 'Koi open round nahi' });
  round.status='closed'; round.closedAt=Date.now(); save(d); res.json({ ok: true });
});

app.post('/admin/round/result', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { winNum } = req.body;
  const num = parseInt(winNum);
  if (isNaN(num)||num<0||num>9) return res.json({ ok: false, msg: '0-9 mein se number daalo' });
  const d = load(); ensureDB(d);
  const round = getCurrentRound(d);
  if (!round||round.status==='result') return res.json({ ok: false, msg: 'Round ready nahi' });
  const mult = d.settings.multiplier||9;
  round.status='result'; round.winNum=num; round.resultAt=Date.now();
  const winners=[];
  (round.bets||[]).forEach(b=>{
    if (b.status==='approved') {
      b.won = b.number===num;
      b.winAmount = b.won ? b.amount*mult : 0;
      if (b.won) {
        const user = d.users.find(u=>u.code===b.userCode);
        if (user) { user.coins = (user.coins||0) + b.winAmount; winners.push({name:b.userName,code:b.userCode,coins:b.winAmount}); }
      }
    }
  });
  d.currentRoundId=null; save(d);
  secLog('ROUND_RESULT', { winNum: num, winners: winners.length });
  res.json({ ok:true, winNum:num, winners });
});

// ─── COIN APPROVE/REJECT ──────────────────────────────────
app.get('/admin/coins', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); ensureDB(d);
  res.json({ ok: true, requests: d.coinRequests.slice().reverse() });
});

app.post('/admin/coins/approve', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body; const d = load(); ensureDB(d);
  const cr = d.coinRequests.find(r=>r.id===reqId);
  if (!cr) return res.json({ ok: false, msg: 'Request nahi mili' });
  if (cr.status !== 'pending') return res.json({ ok: false, msg: 'Already processed' });
  // Double-check UTR not already approved
  const alreadyApproved = d.coinRequests.find(r => r.id !== reqId && r.utr === cr.utr && r.status === 'approved');
  if (alreadyApproved) {
    secLog('DUPLICATE_UTR_APPROVE_ATTEMPT', { utr: cr.utr, reqId });
    return res.json({ ok: false, msg: 'Yeh UTR pehle approve ho chuka hai! Reject karo.' });
  }
  const user = d.users.find(u=>u.code===cr.userCode);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  user.coins = (user.coins||0) + cr.coins;
  cr.status = 'approved'; cr.processedAt = Date.now();
  // Add to permanent blocked list to prevent reuse
  if (!(d.blockedUTRs||[]).includes(cr.utr)) { d.blockedUTRs = [...(d.blockedUTRs||[]), cr.utr]; }
  save(d);
  secLog('COIN_APPROVED', { code: cr.userCode, utr: cr.utr, coins: cr.coins });
  res.json({ ok: true, coins: user.coins });
});

app.post('/admin/coins/reject', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId, blockUTR } = req.body; const d = load(); ensureDB(d);
  const cr = d.coinRequests.find(r=>r.id===reqId);
  if (!cr) return res.json({ ok: false, msg: 'Request nahi mili' });
  cr.status = 'rejected'; cr.processedAt = Date.now();
  if (blockUTR && !(d.blockedUTRs||[]).includes(cr.utr)) {
    d.blockedUTRs = [...(d.blockedUTRs||[]), cr.utr];
    secLog('UTR_BLOCKED', { utr: cr.utr, code: cr.userCode });
  }
  save(d);
  res.json({ ok: true });
});

// ─── WITHDRAW APPROVE/REJECT ──────────────────────────────
app.get('/admin/withdraw', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); ensureDB(d);
  res.json({ ok: true, requests: d.withdrawRequests.slice().reverse() });
});

app.post('/admin/withdraw/done', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body; const d = load(); ensureDB(d);
  const wr = d.withdrawRequests.find(r=>r.id===reqId);
  if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
  if (wr.status !== 'pending') return res.json({ ok: false, msg: 'Already processed' });
  wr.status = 'paid'; wr.paidAt = Date.now();
  save(d);
  secLog('WITHDRAW_PAID', { code: wr.userCode, coins: wr.coins, upiId: wr.upiId });
  res.json({ ok: true });
});

app.post('/admin/withdraw/reject', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body; const d = load(); ensureDB(d);
  const wr = d.withdrawRequests.find(r=>r.id===reqId);
  if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
  if (wr.status !== 'pending') return res.json({ ok: false, msg: 'Already processed' });
  // Refund coins
  const user = d.users.find(u=>u.code===wr.userCode);
  if (user) user.coins = (user.coins||0) + wr.coins;
  wr.status = 'rejected'; wr.processedAt = Date.now();
  save(d);
  secLog('WITHDRAW_REJECTED', { code: wr.userCode, coins: wr.coins });
  res.json({ ok: true });
});

// ─── USER MANAGEMENT + AUDIT ──────────────────────────────
app.post('/admin/user', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { name } = req.body; const d = load(); const code = genCode();
  d.users.push({ code, name:name||'User', createdAt:Date.now(), deviceId:null, coins:0, suspicious:0 });
  save(d); res.json({ ok:true, code, name:name||'User' });
});

app.delete('/admin/user/:code', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); d.users = d.users.filter(u=>u.code!==req.params.code); save(d); res.json({ ok: true });
});

app.post('/admin/user/resetdevice', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code } = req.body; const d = load();
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false });
  user.deviceId=null; save(d); res.json({ ok: true });
});

app.post('/admin/user/ban', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code, ban } = req.body; const d = load();
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false });
  user.banned = !!ban;
  save(d);
  secLog(ban?'USER_BANNED':'USER_UNBANNED', { code });
  res.json({ ok: true });
});

app.post('/admin/user/coins', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code, coins, reason } = req.body; const d = load();
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false });
  const oldCoins = user.coins || 0;
  user.coins = Math.max(0, parseInt(coins)||0);
  save(d);
  secLog('ADMIN_COIN_ADJUST', { code, from: oldCoins, to: user.coins, reason: reason||'manual' });
  res.json({ ok: true, coins: user.coins });
});

// User full audit trail
app.get('/admin/user/audit/:code', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); ensureDB(d);
  const code = req.params.code;
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false });
  const audit = buildUserAudit(d, code);
  const coinBuys = d.coinRequests.filter(r=>r.userCode===code);
  const withdrawals = d.withdrawRequests.filter(r=>r.userCode===code);
  const bets = d.rounds.flatMap(r => (r.bets||[]).filter(b=>b.userCode===code).map(b=>({...b, roundWinNum:r.winNum, resultAt:r.resultAt})));
  return res.json({ ok: true, user, audit, coinBuys, withdrawals, bets });
});

// Block/unblock IP
app.post('/admin/blockip', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { ip, block } = req.body; const d = load(); ensureDB(d);
  if (block) { if (!(d.blockedIPs||[]).includes(ip)) d.blockedIPs.push(ip); }
  else { d.blockedIPs = (d.blockedIPs||[]).filter(x=>x!==ip); }
  save(d);
  secLog(block?'IP_BLOCKED':'IP_UNBLOCKED', { ip });
  res.json({ ok: true });
});

// Get security log (last 200 entries)
app.get('/admin/seclog', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  try {
    const raw = fs.existsSync(LOG) ? fs.readFileSync(LOG,'utf8') : '';
    const lines = raw.trim().split('\n').filter(Boolean).slice(-200).reverse().map(l=>{try{return JSON.parse(l);}catch(e){return null;}}).filter(Boolean);
    res.json({ ok: true, logs: lines });
  } catch(e) { res.json({ ok: true, logs: [] }); }
});

app.post('/admin/settings', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { upiId,upiName,minBet,maxBet,multiplier,tgLink,minWithdraw,coinRate,maxCoinBuyPerDay,maxWithdrawPerDay } = req.body;
  const d = load(); ensureDB(d);
  if (upiId!==undefined) d.settings.upiId=upiId;
  if (upiName!==undefined) d.settings.upiName=upiName;
  if (minBet!==undefined&&minBet!=='') d.settings.minBet=parseInt(minBet);
  if (maxBet!==undefined&&maxBet!=='') d.settings.maxBet=parseInt(maxBet);
  if (multiplier!==undefined&&multiplier!=='') d.settings.multiplier=parseInt(multiplier);
  if (tgLink!==undefined) d.settings.tgLink=tgLink;
  if (minWithdraw!==undefined&&minWithdraw!=='') d.settings.minWithdraw=parseInt(minWithdraw);
  if (coinRate!==undefined&&coinRate!=='') d.settings.coinRate=parseFloat(coinRate);
  if (maxCoinBuyPerDay!==undefined&&maxCoinBuyPerDay!=='') d.settings.maxCoinBuyPerDay=parseInt(maxCoinBuyPerDay);
  if (maxWithdrawPerDay!==undefined&&maxWithdrawPerDay!=='') d.settings.maxWithdrawPerDay=parseInt(maxWithdrawPerDay);
  save(d); res.json({ ok:true, settings:d.settings });
});

app.get('/admin/history', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  res.json({ ok:true, history: d.rounds.filter(r=>r.status==='result').reverse() });
});

app.listen(PORT, '0.0.0.0', () => console.log('Secure server on ' + PORT));
