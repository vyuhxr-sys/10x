const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'ADMIN2026';

// 🔥 FIREBASE INIT
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
  })
});

const db = admin.firestore();

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

// 🔹 DEFAULT DATA
function defaultData() {
  return {
    users: [],
    rounds: [],
    currentRoundId: null,
    withdrawRequests: [],
    coinRequests: [],
    blockedDevices: [],
    blockedUTRs: [],
    securityLog: [],
    settings: {
      upiId: '',
      upiName: 'Admin',
      minBet: 10,
      maxBet: 5000,
      multiplier: 9,
      tgLink: '',
      minWithdraw: 300,
      coinRate: 1,
      maxDailyCoins: 50000
    }
  };
}

// 🔹 LOAD
async function load() {
  const ref = db.collection('app').doc('data');
  const doc = await ref.get();

  if (!doc.exists) {
    const d = defaultData();
    await ref.set(d);
    return d;
  }

  return doc.data();
}

// 🔹 SAVE
async function save(data) {
  await db.collection('app').doc('data').set(data);
}

// 🔹 LOGIN
app.post('/login', async (req, res) => {
  const { code } = req.body;
  const data = await load();

  const user = data.users.find(u => u.code === code?.toUpperCase());
  if (!user) return res.json({ ok: false, msg: 'Invalid code' });

  return res.json({
    ok: true,
    user: {
      code: user.code,
      name: user.name,
      coins: user.coins || 0
    },
    settings: data.settings
  });
});

// 🔹 VERIFY
app.post('/verify', async (req, res) => {
  const { code } = req.body;
  const data = await load();

  const user = data.users.find(u => u.code === code?.toUpperCase());
  if (!user) return res.json({ ok: false });

  return res.json({
    ok: true,
    user,
    settings: data.settings
  });
});

// 🔹 ROUND INFO
app.get('/round', async (req, res) => {
  const data = await load();

  const round = data.rounds.find(r => r.id === data.currentRoundId);

  res.json({
    ok: true,
    round: round || null,
    settings: data.settings
  });
});

// 🔹 PLACE BET
app.post('/bet', async (req, res) => {
  const { code, number, amount } = req.body;
  const data = await load();

  const user = data.users.find(u => u.code === code?.toUpperCase());
  const round = data.rounds.find(r => r.id === data.currentRoundId);

  if (!user) return res.json({ ok: false, msg: 'User not found' });
  if (!round) return res.json({ ok: false, msg: 'No round' });

  if ((user.coins || 0) < amount) {
    return res.json({ ok: false, msg: 'Coins kam hain' });
  }

  user.coins -= amount;

  if (!round.bets) round.bets = [];

  round.bets.push({
    userCode: user.code,
    number,
    amount,
    status: 'approved',
    placedAt: Date.now()
  });

  await save(data);

  res.json({ ok: true, coins: user.coins });
});

// 🔹 CREATE ROUND (ADMIN)
app.post('/admin/createRound', async (req, res) => {
  if (req.headers['x-pass'] !== ADMIN_PASS) {
    return res.json({ ok: false });
  }

  const data = await load();

  const newRound = {
    id: Date.now().toString(),
    status: 'open',
    startedAt: Date.now(),
    bets: []
  };

  data.rounds.push(newRound);
  data.currentRoundId = newRound.id;

  await save(data);

  res.json({ ok: true });
});

// 🔹 RESULT DECLARE (ADMIN)
app.post('/admin/result', async (req, res) => {
  if (req.headers['x-pass'] !== ADMIN_PASS) {
    return res.json({ ok: false });
  }

  const { winNum } = req.body;
  const data = await load();

  const round = data.rounds.find(r => r.id === data.currentRoundId);
  if (!round) return res.json({ ok: false });

  round.status = 'result';
  round.winNum = winNum;
  round.resultAt = Date.now();

  // WIN LOGIC
  round.bets.forEach(b => {
    if (b.number == winNum) {
      b.won = true;
      const user = data.users.find(u => u.code === b.userCode);
      const winAmt = b.amount * data.settings.multiplier;
      user.coins += winAmt;
      b.winAmount = winAmt;
    } else {
      b.won = false;
      b.winAmount = 0;
    }
  });

  await save(data);

  res.json({ ok: true });
});

// 🔹 ADD USER
app.post('/admin/addUser', async (req, res) => {
  if (req.headers['x-pass'] !== ADMIN_PASS) {
    return res.json({ ok: false });
  }

  const { name, code } = req.body;
  const data = await load();

  data.users.push({
    name,
    code: code.toUpperCase(),
    coins: 0
  });

  await save(data);

  res.json({ ok: true });
});

// 🔹 START
app.listen(PORT, () => {
  console.log('🔥 FULL Firebase Server Running on ' + PORT);
});
