const express = require('express');
const cors = require('cors');
const fs = require('fs');
const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'BETADMIN2026';
const DATA = './bet-db.json';

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

// ─── DB HELPERS ───────────────────────────────────────────
function load() {
  try {
    if (fs.existsSync(DATA)) return JSON.parse(fs.readFileSync(DATA, 'utf8'));
  } catch (e) {}
  return {
    users: [],           // { code, name, createdAt }
    rounds: [],          // { id, status:'open'|'closed'|'result', openedAt, closedAt, winNum, bets:[] }
    settings: {
      upiId: 'your-upi@paytm',
      upiName: 'Admin Name',
      minBet: 100,
      maxBet: 50000,
      multiplier: 9
    },
    stats: { totalBets: 0, totalAmount: 0, totalPayout: 0 }
  };
}
function save(d) { try { fs.writeFileSync(DATA, JSON.stringify(d, null, 2)); } catch (e) {} }
function auth(req) { return req.headers['x-pass'] === ADMIN_PASS; }
function genId() { return Date.now().toString(36) + Math.random().toString(36).substr(2, 4); }

function getCurrentRound(d) {
  return d.rounds.find(r => r.status === 'open' || r.status === 'closed') || null;
}

// ─── PUBLIC: User verify (access code login) ──────────────
app.post('/user/login', (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false, msg: 'Code daalo' });
  const d = load();
  const user = d.users.find(u => u.code === code.trim().toUpperCase());
  if (!user) return res.json({ ok: false, msg: 'Galat code — Admin se contact karo' });
  return res.json({ ok: true, user: { code: user.code, name: user.name } });
});

// ─── PUBLIC: Get current round info ───────────────────────
app.get('/round/current', (req, res) => {
  const d = load();
  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: true, round: null });

  // Hide winNum if result not declared yet
  const safe = { ...round };
  if (round.status !== 'result') delete safe.winNum;

  // Aggregate bets per number (totals only, no user details for public)
  const numTotals = {};
  for (let i = 0; i <= 9; i++) numTotals[i] = 0;
  round.bets.forEach(b => {
    if (b.status === 'approved') numTotals[b.number] = (numTotals[b.number] || 0) + b.amount;
  });
  safe.numTotals = numTotals;

  return res.json({ ok: true, round: safe, settings: d.settings });
});

// ─── PUBLIC: Place bet ────────────────────────────────────
app.post('/bet/place', (req, res) => {
  const { userCode, number, amount, utr } = req.body;

  // Validations
  if (!userCode || number === undefined || !amount || !utr)
    return res.json({ ok: false, msg: 'Saari details daalo' });

  const d = load();
  const user = d.users.find(u => u.code === userCode.trim().toUpperCase());
  if (!user) return res.json({ ok: false, msg: 'Invalid user code' });

  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: false, msg: 'Abhi koi round open nahi hai' });
  if (round.status !== 'open') return res.json({ ok: false, msg: 'Betting band ho gayi hai, result ka wait karo' });

  const num = parseInt(number);
  if (isNaN(num) || num < 0 || num > 9) return res.json({ ok: false, msg: 'Number 0-9 ke beech hona chahiye' });

  const amt = parseInt(amount);
  if (isNaN(amt) || amt < d.settings.minBet || amt > d.settings.maxBet)
    return res.json({ ok: false, msg: `Amount ₹${d.settings.minBet} se ₹${d.settings.maxBet} ke beech hona chahiye` });

  // UTR validation: must be numeric, 12 digits
  const cleanUTR = utr.toString().trim();
  if (!/^\d{12}$/.test(cleanUTR))
    return res.json({ ok: false, msg: 'UTR number 12 digits ka hona chahiye (sirf numbers)' });

  // Duplicate UTR check (across ALL rounds)
  const allBets = d.rounds.flatMap(r => r.bets);
  if (allBets.find(b => b.utr === cleanUTR))
    return res.json({ ok: false, msg: 'Yeh UTR pehle se use ho chuka hai' });

  // One pending/approved bet per round per user
  const existingBet = round.bets.find(b => b.userCode === userCode.trim().toUpperCase() && (b.status === 'pending' || b.status === 'approved'));
  if (existingBet) return res.json({ ok: false, msg: 'Aapki bet pehle se hai is round mein' });

  const bet = {
    id: genId(),
    userCode: user.code,
    userName: user.name,
    number: num,
    amount: amt,
    utr: cleanUTR,
    status: 'pending',  // pending → approved / rejected
    placedAt: Date.now(),
    approvedAt: null,
    winAmount: null
  };

  round.bets.push(bet);
  d.stats.totalBets += 1;
  save(d);

  return res.json({ ok: true, bet: { id: bet.id, number: num, amount: amt, status: 'pending' }, msg: 'Bet placed! Admin verify karega.' });
});

// ─── PUBLIC: Check my bet status ──────────────────────────
app.post('/bet/mystatus', (req, res) => {
  const { userCode } = req.body;
  if (!userCode) return res.json({ ok: false });
  const d = load();
  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: true, bet: null, round: null });

  const bet = round.bets.find(b => b.userCode === userCode.trim().toUpperCase());
  const roundInfo = { status: round.status, id: round.id };
  if (round.status === 'result') roundInfo.winNum = round.winNum;

  return res.json({ ok: true, bet: bet || null, round: roundInfo });
});

// ─── ADMIN: Get full data ─────────────────────────────────
app.get('/admin/data', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  const round = getCurrentRound(d);

  // Per-number stats for current round
  let numStats = null;
  if (round) {
    numStats = {};
    for (let i = 0; i <= 9; i++) numStats[i] = { count: 0, total: 0, users: [] };
    round.bets.filter(b => b.status === 'approved').forEach(b => {
      numStats[b.number].count += 1;
      numStats[b.number].total += b.amount;
      numStats[b.number].users.push({ name: b.userName, code: b.userCode, amount: b.amount });
    });
  }

  return res.json({ ok: true, ...d, currentRound: round, numStats });
});

// ─── ADMIN: Create user code ───────────────────────────────
app.post('/admin/user', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { name } = req.body;
  const d = load();
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i++) { if (i === 4) code += '-'; code += chars[Math.floor(Math.random() * chars.length)]; }
  d.users.push({ code, name: name || 'User', createdAt: Date.now() });
  save(d);
  res.json({ ok: true, code, name });
});

// ─── ADMIN: Delete user ────────────────────────────────────
app.delete('/admin/user/:code', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  d.users = d.users.filter(u => u.code !== req.params.code);
  save(d);
  res.json({ ok: true });
});

// ─── ADMIN: Open new round ─────────────────────────────────
app.post('/admin/round/open', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  const existing = getCurrentRound(d);
  if (existing) return res.json({ ok: false, msg: 'Pehle current round close/result karo' });

  const round = {
    id: genId(),
    status: 'open',
    openedAt: Date.now(),
    closedAt: null,
    resultAt: null,
    winNum: null,
    bets: []
  };
  d.rounds.push(round);
  save(d);
  res.json({ ok: true, round });
});

// ─── ADMIN: Close betting (stop new bets) ─────────────────
app.post('/admin/round/close', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  const round = getCurrentRound(d);
  if (!round || round.status !== 'open') return res.json({ ok: false, msg: 'Koi open round nahi hai' });
  round.status = 'closed';
  round.closedAt = Date.now();
  save(d);
  res.json({ ok: true });
});

// ─── ADMIN: Declare result ────────────────────────────────
app.post('/admin/round/result', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { winNum } = req.body;
  const num = parseInt(winNum);
  if (isNaN(num) || num < 0 || num > 9) return res.json({ ok: false, msg: 'Valid number 0-9 daalo' });

  const d = load();
  const round = getCurrentRound(d);
  if (!round || round.status === 'result') return res.json({ ok: false, msg: 'Round result ready nahi' });

  round.status = 'result';
  round.winNum = num;
  round.resultAt = Date.now();

  // Calculate winnings
  const mult = d.settings.multiplier || 9;
  const winners = [];
  round.bets.forEach(b => {
    if (b.status === 'approved' && b.number === num) {
      b.winAmount = b.amount * mult;
      b.won = true;
      winners.push({ name: b.userName, code: b.userCode, amount: b.amount, winAmount: b.winAmount });
      d.stats.totalPayout += b.winAmount;
    } else if (b.status === 'approved') {
      b.won = false;
      b.winAmount = 0;
    }
  });

  const totalCollected = round.bets.filter(b => b.status === 'approved').reduce((s, b) => s + b.amount, 0);
  d.stats.totalAmount += totalCollected;
  save(d);

  res.json({ ok: true, winNum: num, winners, totalCollected });
});

// ─── ADMIN: Approve / Reject bet ──────────────────────────
app.post('/admin/bet/verify', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { betId, action } = req.body; // action: 'approve' | 'reject'
  const d = load();
  const round = getCurrentRound(d);
  if (!round) return res.json({ ok: false, msg: 'No active round' });

  const bet = round.bets.find(b => b.id === betId);
  if (!bet) return res.json({ ok: false, msg: 'Bet nahi mila' });

  bet.status = action === 'approve' ? 'approved' : 'rejected';
  bet.approvedAt = Date.now();
  save(d);
  res.json({ ok: true, status: bet.status });
});

// ─── ADMIN: Mark winner as paid ───────────────────────────
app.post('/admin/bet/paid', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { betId } = req.body;
  const d = load();
  // Search across all rounds
  for (const round of d.rounds) {
    const bet = round.bets.find(b => b.id === betId);
    if (bet) { bet.paid = true; bet.paidAt = Date.now(); save(d); return res.json({ ok: true }); }
  }
  res.json({ ok: false, msg: 'Bet nahi mila' });
});

// ─── ADMIN: Update settings ───────────────────────────────
app.post('/admin/settings', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { upiId, upiName, minBet, maxBet, multiplier } = req.body;
  const d = load();
  if (upiId) d.settings.upiId = upiId;
  if (upiName) d.settings.upiName = upiName;
  if (minBet) d.settings.minBet = parseInt(minBet);
  if (maxBet) d.settings.maxBet = parseInt(maxBet);
  if (multiplier) d.settings.multiplier = parseInt(multiplier);
  save(d);
  res.json({ ok: true, settings: d.settings });
});

// ─── ADMIN: Round history ─────────────────────────────────
app.get('/admin/history', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  const history = d.rounds.filter(r => r.status === 'result').slice(-20).reverse();
  res.json({ ok: true, history });
});

app.listen(PORT, '0.0.0.0', () => console.log('BET SERVER running on port ' + PORT));
