const express = require('express');
const cors = require('cors');
const fs = require('fs');
const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'ADMIN2026';
const DATA = './db.json';

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

function load() {
  try { if (fs.existsSync(DATA)) return JSON.parse(fs.readFileSync(DATA, 'utf8')); } catch(e){}
  return { users: [], rounds: [], currentRoundId: null, settings: { upiId: '', upiName: 'Admin', minBet: 10, maxBet: 5000, multiplier: 9, tgLink: 'https://t.me/Winx1010' } };
}
function save(d) { try { fs.writeFileSync(DATA, JSON.stringify(d, null, 2)); } catch(e){} }
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

// Auto-close betting at 40 min
setInterval(() => {
  try {
    const d = load();
    const round = getCurrentRound(d);
    if (!round || round.status !== 'open') return;
    if (Date.now() >= round.startedAt + 40*60*1000) {
      round.status = 'closed'; round.closedAt = Date.now();
      save(d); console.log('Auto-closed round', round.id);
    }
  } catch(e){}
}, 15000);

// LOGIN
app.post('/login', (req, res) => {
  const { code, deviceId } = req.body;
  if (!code) return res.json({ ok: false, msg: 'Code daalo' });
  const d = load();
  const user = d.users.find(u => u.code === code.trim().toUpperCase());
  if (!user) return res.json({ ok: false, msg: 'Galat code — Telegram se lo: @Winx1010' });
  if (!user.deviceId && deviceId) { user.deviceId = deviceId; save(d); }
  else if (user.deviceId && deviceId && user.deviceId !== deviceId)
    return res.json({ ok: false, msg: 'Yeh code doosre phone pe use ho chuka hai' });
  return res.json({ ok: true, user: { code: user.code, name: user.name }, settings: d.settings });
});

// ROUND INFO (public)
app.get('/round', (req, res) => {
  const d = load();
  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: true, round: null, settings: d.settings });
  const info = { id: round.id, status: round.status, startedAt: round.startedAt, betEndsAt: round.startedAt+40*60*1000, roundEndsAt: round.startedAt+60*60*1000, winNum: round.status==='result'?round.winNum:null };
  return res.json({ ok: true, round: info, settings: d.settings });
});

// MY BET STATUS
app.post('/mybetStatus', (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = load();
  const cleanCode = code.trim().toUpperCase();
  let round = getCurrentRound(d);
  if (!round) { const done = d.rounds.filter(r=>r.status==='result'); round = done.length?done[done.length-1]:null; }
  if (!round) return res.json({ ok: true, bet: null, round: null, settings: d.settings });
  const bet = (round.bets||[]).find(b => b.userCode === cleanCode);
  const ri = { id:round.id, status:round.status, startedAt:round.startedAt, betEndsAt:round.startedAt+40*60*1000, roundEndsAt:round.startedAt+60*60*1000, winNum:round.status==='result'?round.winNum:null };
  return res.json({ ok: true, bet: bet||null, round: ri, settings: d.settings });
});

// PLACE BET
app.post('/bet', (req, res) => {
  const { code, number, amount, utr, userUpi } = req.body;
  if (!code||number===undefined||!amount||!utr||!userUpi) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = load();
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user) return res.json({ ok: false, msg: 'Invalid code' });
  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: false, msg: 'Koi round nahi chala abhi' });
  if (round.status !== 'open') return res.json({ ok: false, msg: 'Betting band ho gayi' });
  const num = parseInt(number);
  if (isNaN(num)||num<0||num>9) return res.json({ ok: false, msg: 'Number 0-9 ke beech hona chahiye' });
  const amt = parseInt(amount);
  if (isNaN(amt)||amt<d.settings.minBet||amt>d.settings.maxBet) return res.json({ ok: false, msg: `Amount Rs.${d.settings.minBet}-${d.settings.maxBet} ke beech hona chahiye` });
  const cleanUTR = utr.toString().trim().replace(/\s/g,'');
  if (!/^\d{6,20}$/.test(cleanUTR)) return res.json({ ok: false, msg: 'UTR sirf numbers hona chahiye (6-20 digit)' });
  const cleanUpi = userUpi.toString().trim();
  if (!cleanUpi) return res.json({ ok: false, msg: 'Apni UPI ID daalo' });
  const allBets = d.rounds.flatMap(r=>r.bets||[]);
  if (allBets.find(b=>b.utr===cleanUTR)) return res.json({ ok: false, msg: 'Yeh UTR pehle use ho chuka hai' });
  const existing = (round.bets||[]).find(b=>b.userCode===cleanCode&&b.status!=='rejected');
  if (existing) return res.json({ ok: false, msg: 'Aapki bet pehle se hai is round mein' });
  if (!round.bets) round.bets = [];
  const bet = { id:uid(), userCode:cleanCode, userName:user.name, number:num, amount:amt, utr:cleanUTR, userUpi:cleanUpi, status:'pending', placedAt:Date.now(), won:null, winAmount:null, paid:false };
  round.bets.push(bet);
  save(d);
  return res.json({ ok: true, bet: { id:bet.id, number:num, amount:amt, status:'pending' } });
});

// ADMIN DATA
app.get('/admin/data', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  const round = getCurrentRound(d);
  let numStats = null;
  if (round && round.bets) {
    numStats = {};
    for (let i=0;i<=9;i++) numStats[i]={count:0,total:0,bets:[]};
    round.bets.filter(b=>b.status==='approved').forEach(b=>{ numStats[b.number].count++; numStats[b.number].total+=b.amount; numStats[b.number].bets.push({name:b.userName,code:b.userCode,amount:b.amount,upi:b.userUpi}); });
  }
  const ri = round ? { ...round, betEndsAt:round.startedAt+40*60*1000, roundEndsAt:round.startedAt+60*60*1000 } : null;
  return res.json({ ok:true, users:d.users, round:ri, numStats, settings:d.settings,
    stats:{ totalUsers:d.users.length, totalRounds:d.rounds.filter(r=>r.status==='result').length,
      currentBets:round?(round.bets||[]).filter(b=>b.status==='approved').length:0,
      currentAmount:round?(round.bets||[]).filter(b=>b.status==='approved').reduce((s,b)=>s+b.amount,0):0 }
  });
});

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
  const { winNum } = req.body; const num = parseInt(winNum);
  if (isNaN(num)||num<0||num>9) return res.json({ ok: false, msg: '0-9 mein se number daalo' });
  const d = load(); const round = getCurrentRound(d);
  if (!round||round.status==='result') return res.json({ ok: false, msg: 'Round result ke liye ready nahi' });
  const mult = d.settings.multiplier||9;
  round.status='result'; round.winNum=num; round.resultAt=Date.now();
  const winners=[];
  (round.bets||[]).forEach(b=>{ if(b.status==='approved'){b.won=b.number===num;b.winAmount=b.won?b.amount*mult:0;if(b.won)winners.push({name:b.userName,upi:b.userUpi,amount:b.amount,winAmount:b.winAmount});} });
  d.currentRoundId=null; save(d);
  res.json({ ok:true, winNum:num, winners });
});

app.post('/admin/bet/verify', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { betId, action } = req.body; const d = load();
  for (const round of d.rounds) {
    const bet = (round.bets||[]).find(b=>b.id===betId);
    if (bet) { bet.status=action==='approve'?'approved':'rejected'; bet.verifiedAt=Date.now(); save(d); return res.json({ ok:true, status:bet.status }); }
  }
  res.json({ ok: false, msg: 'Bet nahi mili' });
});

app.post('/admin/bet/paid', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { betId } = req.body; const d = load();
  for (const round of d.rounds) { const bet=(round.bets||[]).find(b=>b.id===betId); if(bet){bet.paid=true;bet.paidAt=Date.now();save(d);return res.json({ok:true});} }
  res.json({ ok: false });
});

app.post('/admin/user', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { name } = req.body; const d = load(); const code = genCode();
  d.users.push({ code, name:name||'User', createdAt:Date.now(), deviceId:null }); save(d);
  res.json({ ok:true, code, name:name||'User' });
});

app.delete('/admin/user/:code', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); d.users = d.users.filter(u=>u.code!==req.params.code); save(d); res.json({ ok: true });
});

app.post('/admin/user/resetdevice', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code } = req.body; const d = load(); const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  user.deviceId=null; save(d); res.json({ ok: true });
});

app.post('/admin/settings', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { upiId, upiName, minBet, maxBet, multiplier, tgLink } = req.body; const d = load();
  if (upiId!==undefined) d.settings.upiId=upiId;
  if (upiName!==undefined) d.settings.upiName=upiName;
  if (minBet!==undefined&&minBet!=='') d.settings.minBet=parseInt(minBet);
  if (maxBet!==undefined&&maxBet!=='') d.settings.maxBet=parseInt(maxBet);
  if (multiplier!==undefined&&multiplier!=='') d.settings.multiplier=parseInt(multiplier);
  if (tgLink!==undefined) d.settings.tgLink=tgLink;
  save(d); res.json({ ok:true, settings:d.settings });
});

app.get('/admin/history', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  res.json({ ok:true, history:d.rounds.filter(r=>r.status==='result').slice(-20).reverse() });
});

app.listen(PORT, '0.0.0.0', () => console.log('Server on ' + PORT));
