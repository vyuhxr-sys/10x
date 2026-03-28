const express = require('express');
const cors = require('cors');
const fs = require('fs');
const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'ADMIN2026';
const DATA = './db.json';

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

// ─── DB HELPERS ───────────────────────────────────────────
function load() {
  try {
    if (fs.existsSync(DATA)) return JSON.parse(fs.readFileSync(DATA, 'utf8'));
  } catch(e) {}
  return {
    users: [],
    rounds: [],
    currentRoundId: null,
    withdrawRequests: [],
    coinRequests: [],
    settings: {
      upiId: '', upiName: 'Admin', minBet: 10, maxBet: 5000,
      multiplier: 9, tgLink: 'https://t.me/Winx1010',
      minWithdraw: 300, coinRate: 1  // 1 coin = ₹1 by default
    }
  };
}
function save(d) { try { fs.writeFileSync(DATA, JSON.stringify(d, null, 2)); } catch(e) {} }
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
// Ensure withdraw & coin arrays exist on old DBs
function ensureArrays(d) {
  if (!d.withdrawRequests) d.withdrawRequests = [];
  if (!d.coinRequests) d.coinRequests = [];
  if (!d.settings.minWithdraw) d.settings.minWithdraw = 300;
  if (!d.settings.coinRate) d.settings.coinRate = 1;
}

// ─── AUTO-CLOSE BETTING AT 40 MIN ─────────────────────────
setInterval(() => {
  try {
    const d = load();
    const round = getCurrentRound(d);
    if (!round || round.status !== 'open') return;
    if (Date.now() >= round.startedAt + 40*60*1000) {
      round.status = 'closed'; round.closedAt = Date.now();
      save(d); console.log('Auto-closed round', round.id);
    }
  } catch(e) {}
}, 15000);

// ─── AUTH ROUTES ──────────────────────────────────────────
app.post('/login', (req, res) => {
  const { code, deviceId } = req.body;
  if (!code) return res.json({ ok: false, msg: 'Code daalo' });
  const d = load(); ensureArrays(d);
  const user = d.users.find(u => u.code === code.trim().toUpperCase());
  if (!user) return res.json({ ok: false, msg: 'Galat code — Telegram se lo: @Winx1010' });
  if (!user.deviceId && deviceId) { user.deviceId = deviceId; save(d); }
  else if (user.deviceId && deviceId && user.deviceId !== deviceId)
    return res.json({ ok: false, msg: 'Yeh code doosre phone pe use ho chuka hai' });
  if (user.coins === undefined) { user.coins = 0; save(d); }
  return res.json({ ok: true, user: { code: user.code, name: user.name, coins: user.coins||0 }, settings: d.settings });
});

app.post('/verify', (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = load(); ensureArrays(d);
  const user = d.users.find(u => u.code === code.trim().toUpperCase());
  if (!user) return res.json({ ok: false, msg: 'Session expire — dobara login karo' });
  if (user.coins === undefined) { user.coins = 0; save(d); }
  return res.json({ ok: true, user: { code: user.code, name: user.name, coins: user.coins||0 }, settings: d.settings });
});

// ─── ROUND INFO (PUBLIC) ─────────────────────────────────
app.get('/round', (req, res) => {
  const d = load();
  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: true, round: null, settings: d.settings });
  const info = {
    id: round.id, status: round.status, startedAt: round.startedAt,
    betEndsAt: round.startedAt+40*60*1000, roundEndsAt: round.startedAt+60*60*1000,
    winNum: round.status==='result' ? round.winNum : null
  };
  return res.json({ ok: true, round: info, settings: d.settings });
});

// ─── MY BET STATUS ───────────────────────────────────────
app.post('/mybetStatus', (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = load(); ensureArrays(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  let round = getCurrentRound(d);
  if (!round) { const done = d.rounds.filter(r=>r.status==='result'); round = done.length ? done[done.length-1] : null; }
  if (!round) return res.json({ ok: true, bet: null, round: null, settings: d.settings, coins: user ? (user.coins||0) : 0 });
  const bet = (round.bets||[]).find(b => b.userCode === cleanCode);
  const ri = { id:round.id, status:round.status, startedAt:round.startedAt, betEndsAt:round.startedAt+40*60*1000, roundEndsAt:round.startedAt+60*60*1000, winNum:round.status==='result'?round.winNum:null };
  return res.json({ ok: true, bet: bet||null, round: ri, settings: d.settings, coins: user ? (user.coins||0) : 0 });
});

// ─── MY HISTORY (user's own round history) ───────────────
app.post('/myhistory', (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = load();
  const cleanCode = code.trim().toUpperCase();
  const history = d.rounds
    .filter(r => r.status === 'result')
    .map(r => {
      const bet = (r.bets||[]).find(b => b.userCode === cleanCode);
      if (!bet || bet.status === 'rejected') return null;
      return {
        roundId: r.id,
        resultAt: r.resultAt,
        winNum: r.winNum,
        myNumber: bet.number,
        myAmount: bet.amount,
        won: bet.won,
        winAmount: bet.winAmount || 0,
        status: bet.status
      };
    })
    .filter(Boolean)
    .reverse()
    .slice(0, 30);
  return res.json({ ok: true, history });
});

// ─── PLACE BET (coin-based) ──────────────────────────────
app.post('/bet', (req, res) => {
  const { code, number, amount } = req.body;
  if (!code || number === undefined || !amount) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = load(); ensureArrays(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user) return res.json({ ok: false, msg: 'Invalid code' });
  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: false, msg: 'Koi round nahi chala abhi' });
  if (round.status !== 'open') return res.json({ ok: false, msg: 'Betting band ho gayi' });
  const num = parseInt(number);
  if (isNaN(num)||num<0||num>9) return res.json({ ok: false, msg: 'Number 0-9 ke beech hona chahiye' });
  const amt = parseInt(amount);
  if (isNaN(amt)||amt<d.settings.minBet||amt>d.settings.maxBet) return res.json({ ok: false, msg: `Amount ${d.settings.minBet}-${d.settings.maxBet} coins ke beech hona chahiye` });
  if ((user.coins||0) < amt) return res.json({ ok: false, msg: `Aapke paas sirf ${user.coins||0} coins hain. Pehle coins kharido.` });
  const existing = (round.bets||[]).find(b => b.userCode===cleanCode && b.status!=='rejected');
  if (existing) return res.json({ ok: false, msg: 'Aapki bet pehle se hai is round mein' });
  // Deduct coins immediately
  user.coins = (user.coins||0) - amt;
  if (!round.bets) round.bets = [];
  const bet = { id:uid(), userCode:cleanCode, userName:user.name, number:num, amount:amt, status:'approved', placedAt:Date.now(), won:null, winAmount:null };
  round.bets.push(bet);
  save(d);
  return res.json({ ok: true, bet: { id:bet.id, number:num, amount:amt, status:'approved' }, coins: user.coins });
});

// ─── COIN PURCHASE REQUEST (user submit karta hai) ───────
app.post('/coins/buy', (req, res) => {
  const { code, utr, amount } = req.body;
  if (!code||!utr||!amount) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = load(); ensureArrays(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user) return res.json({ ok: false, msg: 'Invalid code' });
  const cleanUTR = utr.toString().trim().replace(/\s/g,'');
  if (!/^\d{6,20}$/.test(cleanUTR)) return res.json({ ok: false, msg: 'UTR sirf numbers (6-20 digit)' });
  // Check duplicate UTR
  const allUTRs = d.coinRequests.map(r=>r.utr).concat(d.rounds.flatMap(r=>(r.bets||[]).map(b=>b.utr)).filter(Boolean));
  if (allUTRs.includes(cleanUTR)) return res.json({ ok: false, msg: 'Yeh UTR pehle use ho chuka hai' });
  const amt = parseInt(amount);
  if (isNaN(amt)||amt<10) return res.json({ ok: false, msg: 'Minimum ₹10 ka coin kharido' });
  const req_obj = { id:uid(), userCode:cleanCode, userName:user.name, utr:cleanUTR, amount:amt, coins:Math.floor(amt*(d.settings.coinRate||1)), status:'pending', createdAt:Date.now() };
  d.coinRequests.push(req_obj);
  save(d);
  return res.json({ ok: true, msg: 'Request bhej di! Admin approve karega jald.' });
});

// ─── WITHDRAW REQUEST ────────────────────────────────────
app.post('/withdraw', (req, res) => {
  const { code, coins, upiId } = req.body;
  if (!code||!coins||!upiId) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = load(); ensureArrays(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user) return res.json({ ok: false, msg: 'Invalid code' });
  const c = parseInt(coins);
  const minW = d.settings.minWithdraw || 300;
  if (isNaN(c)||c<minW) return res.json({ ok: false, msg: `Minimum ${minW} coins withdraw kar sakte ho` });
  if ((user.coins||0) < c) return res.json({ ok: false, msg: `Aapke paas sirf ${user.coins||0} coins hain` });
  const cleanUpi = upiId.toString().trim();
  if (!cleanUpi) return res.json({ ok: false, msg: 'UPI ID daalo' });
  // Deduct coins immediately, request pending
  user.coins = (user.coins||0) - c;
  const req_obj = { id:uid(), userCode:cleanCode, userName:user.name, coins:c, upiId:cleanUpi, status:'pending', createdAt:Date.now() };
  d.withdrawRequests.push(req_obj);
  save(d);
  return res.json({ ok: true, msg: `${c} coins withdraw request bhej di! Admin jald process karega.`, coins: user.coins });
});

// ─── ADMIN DATA ──────────────────────────────────────────
app.get('/admin/data', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); ensureArrays(d);
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
  return res.json({
    ok: true, users: d.users, round: ri, numStats, settings: d.settings,
    pendingCoins, pendingWithdraw,
    stats: {
      totalUsers: d.users.length,
      totalRounds: d.rounds.filter(r=>r.status==='result').length,
      currentBets: round ? (round.bets||[]).filter(b=>b.status==='approved').length : 0,
      currentAmount: round ? (round.bets||[]).filter(b=>b.status==='approved').reduce((s,b)=>s+b.amount,0) : 0
    }
  });
});

// ─── ROUND CONTROLS ──────────────────────────────────────
app.post('/admin/round/start', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  if (getCurrentRound(d)) return res.json({ ok: false, msg: 'Pehle current round finish karo' });
  const round = { id:uid(), status:'open', startedAt:Date.now(), closedAt:null, resultAt:null, winNum:null, bets:[] };
  d.rounds.push(round); d.currentRoundId = round.id; save(d);
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
  const d = load(); ensureArrays(d);
  const round = getCurrentRound(d);
  if (!round||round.status==='result') return res.json({ ok: false, msg: 'Round result ke liye ready nahi' });
  const mult = d.settings.multiplier||9;
  round.status='result'; round.winNum=num; round.resultAt=Date.now();
  const winners=[];
  (round.bets||[]).forEach(b=>{
    if (b.status==='approved') {
      b.won = b.number===num;
      b.winAmount = b.won ? b.amount*mult : 0;
      if (b.won) {
        // Auto-credit coins to winner
        const user = d.users.find(u=>u.code===b.userCode);
        if (user) {
          user.coins = (user.coins||0) + b.winAmount;
          winners.push({ name:b.userName, code:b.userCode, coins:b.winAmount });
        }
      }
    }
  });
  d.currentRoundId=null; save(d);
  res.json({ ok:true, winNum:num, winners });
});

// ─── BET VERIFY (kept for compatibility, not needed in coin flow) ─
app.post('/admin/bet/verify', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { betId, action } = req.body; const d = load();
  for (const round of d.rounds) {
    const bet = (round.bets||[]).find(b=>b.id===betId);
    if (bet) { bet.status=action==='approve'?'approved':'rejected'; bet.verifiedAt=Date.now(); save(d); return res.json({ ok:true, status:bet.status }); }
  }
  res.json({ ok: false, msg: 'Bet nahi mili' });
});

// ─── COIN REQUESTS (admin) ───────────────────────────────
app.get('/admin/coins', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); ensureArrays(d);
  res.json({ ok: true, requests: d.coinRequests.slice().reverse() });
});

app.post('/admin/coins/approve', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body; const d = load(); ensureArrays(d);
  const cr = d.coinRequests.find(r=>r.id===reqId);
  if (!cr) return res.json({ ok: false, msg: 'Request nahi mili' });
  if (cr.status !== 'pending') return res.json({ ok: false, msg: 'Already processed' });
  const user = d.users.find(u=>u.code===cr.userCode);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  user.coins = (user.coins||0) + cr.coins;
  cr.status = 'approved'; cr.processedAt = Date.now();
  save(d);
  res.json({ ok: true, coins: user.coins });
});

app.post('/admin/coins/reject', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body; const d = load(); ensureArrays(d);
  const cr = d.coinRequests.find(r=>r.id===reqId);
  if (!cr) return res.json({ ok: false, msg: 'Request nahi mili' });
  cr.status = 'rejected'; cr.processedAt = Date.now();
  save(d);
  res.json({ ok: true });
});

// ─── WITHDRAW REQUESTS (admin) ───────────────────────────
app.get('/admin/withdraw', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); ensureArrays(d);
  res.json({ ok: true, requests: d.withdrawRequests.slice().reverse() });
});

app.post('/admin/withdraw/done', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body; const d = load(); ensureArrays(d);
  const wr = d.withdrawRequests.find(r=>r.id===reqId);
  if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
  wr.status = 'paid'; wr.paidAt = Date.now();
  save(d);
  res.json({ ok: true });
});

app.post('/admin/withdraw/reject', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body; const d = load(); ensureArrays(d);
  const wr = d.withdrawRequests.find(r=>r.id===reqId);
  if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
  // Refund coins
  const user = d.users.find(u=>u.code===wr.userCode);
  if (user) user.coins = (user.coins||0) + wr.coins;
  wr.status = 'rejected'; wr.processedAt = Date.now();
  save(d);
  res.json({ ok: true });
});

// ─── USER MANAGEMENT ─────────────────────────────────────
app.post('/admin/user', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { name } = req.body; const d = load(); const code = genCode();
  d.users.push({ code, name:name||'User', createdAt:Date.now(), deviceId:null, coins:0 }); save(d);
  res.json({ ok:true, code, name:name||'User' });
});

app.delete('/admin/user/:code', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); d.users = d.users.filter(u=>u.code!==req.params.code); save(d); res.json({ ok: true });
});

app.post('/admin/user/resetdevice', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code } = req.body; const d = load();
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  user.deviceId=null; save(d); res.json({ ok: true });
});

// Admin manually adjust coins
app.post('/admin/user/coins', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code, coins } = req.body; const d = load();
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  user.coins = Math.max(0, parseInt(coins)||0);
  save(d); res.json({ ok: true, coins: user.coins });
});

// ─── SETTINGS ────────────────────────────────────────────
app.post('/admin/settings', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { upiId, upiName, minBet, maxBet, multiplier, tgLink, minWithdraw, coinRate } = req.body;
  const d = load(); ensureArrays(d);
  if (upiId!==undefined) d.settings.upiId=upiId;
  if (upiName!==undefined) d.settings.upiName=upiName;
  if (minBet!==undefined&&minBet!=='') d.settings.minBet=parseInt(minBet);
  if (maxBet!==undefined&&maxBet!=='') d.settings.maxBet=parseInt(maxBet);
  if (multiplier!==undefined&&multiplier!=='') d.settings.multiplier=parseInt(multiplier);
  if (tgLink!==undefined) d.settings.tgLink=tgLink;
  if (minWithdraw!==undefined&&minWithdraw!=='') d.settings.minWithdraw=parseInt(minWithdraw);
  if (coinRate!==undefined&&coinRate!=='') d.settings.coinRate=parseFloat(coinRate);
  save(d); res.json({ ok:true, settings:d.settings });
});

// ─── HISTORY ─────────────────────────────────────────────
app.get('/admin/history', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  const history = d.rounds.filter(r=>r.status==='result').reverse();
  res.json({ ok:true, history });
});

app.delete('/admin/history/:roundId', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  const before = d.rounds.length;
  d.rounds = d.rounds.filter(r => r.id !== req.params.roundId);
  if (d.rounds.length === before) return res.json({ ok: false, msg: 'Round nahi mila' });
  save(d); res.json({ ok: true });
});

app.delete('/admin/history', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  d.rounds = d.rounds.filter(r => r.status !== 'result');
  save(d); res.json({ ok: true });
});

app.listen(PORT, '0.0.0.0', () => console.log('Server on ' + PORT));
