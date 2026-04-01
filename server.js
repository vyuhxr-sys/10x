const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'ADMIN2026';
const MONGO_URI = process.env.MONGO_URI;

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

// ─── MONGODB ──────────────────────────────────────────────
let db = null;

async function connectDB() {
  if (db) return db;
  const client = new MongoClient(MONGO_URI, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
  });
  await client.connect();
  db = client.db('numbet');
  console.log('MongoDB connected!');
  await db.collection('users').createIndex({ code: 1 }, { unique: true });
  await db.collection('coinRequests').createIndex({ utr: 1 });
  await db.collection('securityLog').createIndex({ at: -1 });
  return db;
}

// ─── HELPERS ──────────────────────────────────────────────
async function getSettings() {
  const s = await db.collection('settings').findOne({ _key: 'main' });
  if (s) return s;
  const def = {
    _key: 'main', upiId: '', upiName: 'Admin',
    minBet: 10, maxBet: 5000, multiplier: 9,
    tgLink: 'https://t.me/Winx1010',
    minWithdraw: 300, coinRate: 1, maxDailyCoins: 50000,
    blockedDevices: [], blockedUTRs: [], currentRoundId: null
  };
  await db.collection('settings').insertOne(def);
  return def;
}

async function saveSettings(s) {
  const { _id, ...rest } = s;
  await db.collection('settings').updateOne({ _key: 'main' }, { $set: rest }, { upsert: true });
}

async function getCurrentRound(settings) {
  if (!settings.currentRoundId) return null;
  return await db.collection('rounds').findOne({ id: settings.currentRoundId }) || null;
}

function uid() { return Date.now().toString(36) + Math.random().toString(36).substr(2, 5).toUpperCase(); }
function genCode() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 8; i++) { if (i === 4) s += '-'; s += c[Math.floor(Math.random() * c.length)]; }
  return s;
}
function auth(req) { return req.headers['x-pass'] === ADMIN_PASS; }
function getIP(req) { return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown'; }

async function secLog(type, data) {
  try {
    await db.collection('securityLog').insertOne({ type, data, at: Date.now() });
    const count = await db.collection('securityLog').countDocuments();
    if (count > 500) {
      const old = await db.collection('securityLog').find().sort({ at: 1 }).limit(count - 500).toArray();
      await db.collection('securityLog').deleteMany({ _id: { $in: old.map(o => o._id) } });
    }
  } catch (e) {}
}

const rateLimiter = {};
function checkRate(key, limit, windowMs) {
  const now = Date.now();
  if (!rateLimiter[key]) rateLimiter[key] = [];
  rateLimiter[key] = rateLimiter[key].filter(t => now - t < windowMs);
  if (rateLimiter[key].length >= limit) return false;
  rateLimiter[key].push(now);
  return true;
}

// ─── DB MIDDLEWARE ────────────────────────────────────────
app.use(async (req, res, next) => {
  try { if (!db) await connectDB(); next(); }
  catch (e) { res.status(503).json({ ok: false, msg: 'Database unavailable. Try again.' }); }
});

// ─── AUTO-CLOSE AT 40 MIN ────────────────────────────────
setInterval(async () => {
  try {
    if (!db) return;
    const settings = await getSettings();
    if (!settings.currentRoundId) return;
    const round = await db.collection('rounds').findOne({ id: settings.currentRoundId });
    if (!round || round.status !== 'open') return;
    if (Date.now() >= round.startedAt + 40 * 60 * 1000) {
      await db.collection('rounds').updateOne({ id: round.id }, { $set: { status: 'closed', closedAt: Date.now() } });
      console.log('Auto-closed round', round.id);
    }
  } catch (e) {}
}, 15000);

// ─── LOGIN ────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { code, deviceId } = req.body;
  const ip = getIP(req);
  if (!code) return res.json({ ok: false, msg: 'Code daalo' });
  if (!checkRate('login:' + ip, 10, 60000)) {
    await secLog('RATE_LIMIT', { ip, code: code.toUpperCase(), action: 'login' });
    return res.json({ ok: false, msg: 'Bahut zyada attempts. 1 minute baad try karo.' });
  }
  const user = await db.collection('users').findOne({ code: code.trim().toUpperCase() });
  if (!user) { await secLog('LOGIN_FAIL', { ip, code: code.trim().toUpperCase() }); return res.json({ ok: false, msg: 'Galat code — Telegram se lo: @Winx1010' }); }
  const settings = await getSettings();
  if (deviceId && (settings.blockedDevices || []).includes(deviceId)) { await secLog('BLOCKED_DEVICE', { ip, code: user.code }); return res.json({ ok: false, msg: 'Yeh device block hai.' }); }
  if (user.banned) { await secLog('BANNED_LOGIN', { ip, code: user.code }); return res.json({ ok: false, msg: 'Account suspend hai. Admin se contact karo.' }); }
  const update = { lastLoginAt: Date.now(), lastLoginIP: ip };
  if (!user.deviceId && deviceId) { update.deviceId = deviceId; update.firstLoginAt = user.firstLoginAt || Date.now(); }
  else if (user.deviceId && deviceId && user.deviceId !== deviceId) {
    await secLog('DEVICE_MISMATCH', { ip, code: user.code, saved: user.deviceId, new: deviceId });
    return res.json({ ok: false, msg: 'Yeh code doosre phone pe use ho chuka hai' });
  }
  await db.collection('users').updateOne({ code: user.code }, { $set: update });
  return res.json({ ok: true, user: { code: user.code, name: user.name, coins: user.coins || 0 }, settings });
});

// ─── VERIFY ───────────────────────────────────────────────
app.post('/verify', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const user = await db.collection('users').findOne({ code: code.trim().toUpperCase() });
  if (!user || user.banned) return res.json({ ok: false, msg: 'Session expire — dobara login karo' });
  const settings = await getSettings();
  return res.json({ ok: true, user: { code: user.code, name: user.name, coins: user.coins || 0 }, settings });
});

// ─── ROUND INFO ───────────────────────────────────────────
app.get('/round', async (req, res) => {
  const settings = await getSettings();
  const round = await getCurrentRound(settings);
  if (!round) return res.json({ ok: true, round: null, settings });
  return res.json({ ok: true, settings, round: { id: round.id, status: round.status, startedAt: round.startedAt, betEndsAt: round.startedAt + 40 * 60 * 1000, roundEndsAt: round.startedAt + 60 * 60 * 1000, winNum: round.status === 'result' ? round.winNum : null } });
});

// ─── MY BET STATUS ────────────────────────────────────────
app.post('/mybetStatus', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const cleanCode = code.trim().toUpperCase();
  const user = await db.collection('users').findOne({ code: cleanCode });
  const settings = await getSettings();
  let round = await getCurrentRound(settings);
  if (!round) { const done = await db.collection('rounds').find({ status: 'result' }).sort({ resultAt: -1 }).limit(1).toArray(); round = done[0] || null; }
  if (!round) return res.json({ ok: true, bet: null, round: null, settings, coins: user ? user.coins || 0 : 0 });
  const bet = (round.bets || []).find(b => b.userCode === cleanCode);
  return res.json({ ok: true, bet: bet || null, settings, coins: user ? user.coins || 0 : 0, round: { id: round.id, status: round.status, startedAt: round.startedAt, betEndsAt: round.startedAt + 40 * 60 * 1000, roundEndsAt: round.startedAt + 60 * 60 * 1000, winNum: round.status === 'result' ? round.winNum : null } });
});

// ─── MY HISTORY ───────────────────────────────────────────
app.post('/myhistory', async (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const cleanCode = code.trim().toUpperCase();
  const rounds = await db.collection('rounds').find({ status: 'result' }).sort({ resultAt: -1 }).limit(50).toArray();
  const history = rounds.map(r => {
    const bet = (r.bets || []).find(b => b.userCode === cleanCode);
    if (!bet || bet.status === 'rejected') return null;
    return { roundId: r.id, resultAt: r.resultAt, winNum: r.winNum, myNumber: bet.number, myAmount: bet.amount, won: bet.won, winAmount: bet.winAmount || 0, status: bet.status };
  }).filter(Boolean);
  return res.json({ ok: true, history });
});

// ─── BET ──────────────────────────────────────────────────
app.post('/bet', async (req, res) => {
  const { code, number, amount } = req.body;
  const ip = getIP(req);
  if (!code || number === undefined || !amount) return res.json({ ok: false, msg: 'Saari details daalo' });
  const cleanCode = code.trim().toUpperCase();
  const user = await db.collection('users').findOne({ code: cleanCode });
  if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });
  const settings = await getSettings();
  const round = await getCurrentRound(settings);
  if (!round || round.status !== 'open') return res.json({ ok: false, msg: round ? 'Betting band ho gayi' : 'Koi round nahi chala abhi' });
  const num = parseInt(number);
  if (isNaN(num) || num < 0 || num > 9) return res.json({ ok: false, msg: 'Number 0-9 ke beech hona chahiye' });
  const amt = parseInt(amount);
  if (isNaN(amt) || amt < settings.minBet || amt > settings.maxBet) return res.json({ ok: false, msg: `Amount ${settings.minBet}-${settings.maxBet} coins ke beech hona chahiye` });
  if ((user.coins || 0) < amt) return res.json({ ok: false, msg: `Sirf ${user.coins || 0} coins hain. Pehle coins kharido.` });
  if ((round.bets || []).find(b => b.userCode === cleanCode && b.status !== 'rejected')) return res.json({ ok: false, msg: 'Aapki bet pehle se hai is round mein' });
  const bet = { id: uid(), userCode: cleanCode, userName: user.name, number: num, amount: amt, status: 'approved', placedAt: Date.now(), ip, won: null, winAmount: null };
  await db.collection('users').updateOne({ code: cleanCode }, { $inc: { coins: -amt } });
  await db.collection('rounds').updateOne({ id: round.id }, { $push: { bets: bet } });
  const u2 = await db.collection('users').findOne({ code: cleanCode });
  return res.json({ ok: true, bet: { id: bet.id, number: num, amount: amt, status: 'approved' }, coins: u2.coins });
});

// ─── COINS BUY ────────────────────────────────────────────
app.post('/coins/buy', async (req, res) => {
  const { code, utr, amount } = req.body;
  const ip = getIP(req);
  if (!code || !utr || !amount) return res.json({ ok: false, msg: 'Saari details daalo' });
  const cleanCode = code.trim().toUpperCase();
  const user = await db.collection('users').findOne({ code: cleanCode });
  if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });
  if (!checkRate('coinbuy:' + cleanCode, 5, 3600000)) return res.json({ ok: false, msg: 'Bahut zyada requests. 1 ghante mein max 5.' });
  const cleanUTR = utr.toString().trim().replace(/\s/g, '');
  if (!/^\d{6,20}$/.test(cleanUTR)) return res.json({ ok: false, msg: 'UTR sirf numbers (6-20 digit)' });
  const settings = await getSettings();
  if ((settings.blockedUTRs || []).includes(cleanUTR)) return res.json({ ok: false, msg: 'Yeh UTR block hai.' });
  if (await db.collection('coinRequests').findOne({ utr: cleanUTR })) { await secLog('DUPLICATE_UTR', { ip, code: cleanCode, utr: cleanUTR }); return res.json({ ok: false, msg: 'Yeh UTR pehle use ho chuka hai' }); }
  const amt = parseInt(amount);
  if (isNaN(amt) || amt < 10) return res.json({ ok: false, msg: 'Minimum ₹10 ka coin kharido' });
  const coinsToAdd = Math.floor(amt * (settings.coinRate || 1));
  const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
  const agg = await db.collection('coinRequests').aggregate([{ $match: { userCode: cleanCode, status: 'approved', createdAt: { $gte: todayStart.getTime() } } }, { $group: { _id: null, total: { $sum: '$coins' } } }]).toArray();
  const todayTotal = agg.length ? agg[0].total : 0;
  if (todayTotal + coinsToAdd > (settings.maxDailyCoins || 50000)) return res.json({ ok: false, msg: `Daily limit ${settings.maxDailyCoins} coins hai. Kal try karo.` });
  await db.collection('coinRequests').insertOne({ id: uid(), userCode: cleanCode, userName: user.name, utr: cleanUTR, amount: amt, coins: coinsToAdd, status: 'pending', createdAt: Date.now(), ip });
  await secLog('COIN_REQUEST', { ip, code: cleanCode, utr: cleanUTR, amount: amt, coins: coinsToAdd });
  return res.json({ ok: true, msg: 'Request bhej di! Admin approve karega jald.' });
});

// ─── WITHDRAW ─────────────────────────────────────────────
app.post('/withdraw', async (req, res) => {
  const { code, coins, upiId } = req.body;
  const ip = getIP(req);
  if (!code || !coins || !upiId) return res.json({ ok: false, msg: 'Saari details daalo' });
  const cleanCode = code.trim().toUpperCase();
  const user = await db.collection('users').findOne({ code: cleanCode });
  if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });
  if (!checkRate('withdraw:' + cleanCode, 3, 3600000)) return res.json({ ok: false, msg: 'Max 3 withdraw requests per hour.' });
  const c = parseInt(coins);
  const settings = await getSettings();
  const minW = settings.minWithdraw || 300;
  if (isNaN(c) || c < minW) return res.json({ ok: false, msg: `Minimum ${minW} coins withdraw kar sakte ho` });
  if ((user.coins || 0) < c) return res.json({ ok: false, msg: `Sirf ${user.coins || 0} coins hain` });
  const cleanUpi = upiId.toString().trim();
  if (!cleanUpi) return res.json({ ok: false, msg: 'UPI ID daalo' });
  await db.collection('users').updateOne({ code: cleanCode }, { $inc: { coins: -c } });
  await db.collection('withdrawRequests').insertOne({ id: uid(), userCode: cleanCode, userName: user.name, coins: c, upiId: cleanUpi, status: 'pending', createdAt: Date.now(), ip });
  await secLog('WITHDRAW_REQUEST', { ip, code: cleanCode, coins: c, upiId: cleanUpi });
  const u2 = await db.collection('users').findOne({ code: cleanCode });
  return res.json({ ok: true, msg: `${c} coins withdraw request bhej di!`, coins: u2.coins });
});

// ─── ADMIN: DATA ──────────────────────────────────────────
app.get('/admin/data', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const settings = await getSettings();
  const round = await getCurrentRound(settings);
  const users = await db.collection('users').find().sort({ createdAt: -1 }).toArray();
  const pendingCoins = await db.collection('coinRequests').countDocuments({ status: 'pending' });
  const pendingWithdraw = await db.collection('withdrawRequests').countDocuments({ status: 'pending' });
  const totalRounds = await db.collection('rounds').countDocuments({ status: 'result' });
  let numStats = null;
  if (round && round.bets) {
    numStats = {};
    for (let i = 0; i <= 9; i++) numStats[i] = { count: 0, total: 0, bets: [] };
    round.bets.filter(b => b.status === 'approved').forEach(b => { numStats[b.number].count++; numStats[b.number].total += b.amount; numStats[b.number].bets.push({ name: b.userName, code: b.userCode, amount: b.amount }); });
  }
  const ri = round ? { ...round, betEndsAt: round.startedAt + 40 * 60 * 1000, roundEndsAt: round.startedAt + 60 * 60 * 1000 } : null;
  return res.json({ ok: true, users, round: ri, numStats, settings, pendingCoins, pendingWithdraw, stats: { totalUsers: users.length, totalRounds, currentBets: round ? (round.bets || []).filter(b => b.status === 'approved').length : 0, currentAmount: round ? (round.bets || []).filter(b => b.status === 'approved').reduce((s, b) => s + b.amount, 0) : 0 } });
});

// ─── ADMIN: SEARCH ────────────────────────────────────────
app.get('/admin/search', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const q = (req.query.q || '').trim();
  if (!q) return res.json({ ok: true, results: [] });
  const results = await db.collection('users').find({ $or: [{ code: { $regex: q.toUpperCase() } }, { name: { $regex: q, $options: 'i' } }] }).limit(20).toArray();
  return res.json({ ok: true, results: results.map(u => ({ code: u.code, name: u.name, coins: u.coins || 0, banned: u.banned || false, lastLoginAt: u.lastLoginAt })) });
});

// ─── ADMIN: USER PROFILE ─────────────────────────────────
app.get('/admin/user/:code', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const code = req.params.code.toUpperCase();
  const user = await db.collection('users').findOne({ code });
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  const coinReqs = await db.collection('coinRequests').find({ userCode: code }).sort({ createdAt: -1 }).toArray();
  const wdReqs = await db.collection('withdrawRequests').find({ userCode: code }).sort({ createdAt: -1 }).toArray();
  const rounds = await db.collection('rounds').find({ status: 'result' }).toArray();
  const allBets = rounds.flatMap(r => { const bet = (r.bets || []).find(b => b.userCode === code); return bet ? [{ ...bet, roundWinNum: r.winNum, resultAt: r.resultAt, roundId: r.id }] : []; });
  const secFlags = await db.collection('securityLog').find({ 'data.code': code, type: { $in: ['DUPLICATE_UTR', 'BLOCKED_UTR_ATTEMPT', 'DEVICE_MISMATCH'] } }).toArray();
  return res.json({ ok: true, user: { code: user.code, name: user.name, coins: user.coins || 0, banned: user.banned || false, deviceId: user.deviceId || null, createdAt: user.createdAt, firstLoginAt: user.firstLoginAt, lastLoginAt: user.lastLoginAt, lastLoginIP: user.lastLoginIP }, coins: { current: user.coins || 0, totalBought: coinReqs.filter(r => r.status === 'approved').reduce((s, r) => s + r.coins, 0), totalWithdrawn: wdReqs.filter(r => r.status === 'paid').reduce((s, r) => s + r.coins, 0) }, bets: { total: allBets.length, wins: allBets.filter(b => b.won).length, losses: allBets.filter(b => b.won === false).length }, coinHistory: coinReqs.slice(0, 20), withdrawHistory: wdReqs.slice(0, 20), betHistory: allBets.slice(-20).reverse(), securityFlags: secFlags, risk: { score: Math.min(secFlags.length * 25, 100), reasons: secFlags.map(f => f.type) } });
});

// ─── ADMIN: ROUND CONTROLS ────────────────────────────────
app.post('/admin/round/start', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const settings = await getSettings();
  if (settings.currentRoundId) return res.json({ ok: false, msg: 'Pehle current round finish karo' });
  const round = { id: uid(), status: 'open', startedAt: Date.now(), closedAt: null, resultAt: null, winNum: null, bets: [] };
  await db.collection('rounds').insertOne(round);
  settings.currentRoundId = round.id;
  await saveSettings(settings);
  await secLog('ROUND_START', { id: round.id });
  res.json({ ok: true, round });
});

app.post('/admin/round/close', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const settings = await getSettings();
  const round = await getCurrentRound(settings);
  if (!round || round.status !== 'open') return res.json({ ok: false, msg: 'Koi open round nahi' });
  await db.collection('rounds').updateOne({ id: round.id }, { $set: { status: 'closed', closedAt: Date.now() } });
  await secLog('ROUND_CLOSE', { id: round.id });
  res.json({ ok: true });
});

app.post('/admin/round/result', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { winNum } = req.body;
  const num = parseInt(winNum);
  if (isNaN(num) || num < 0 || num > 9) return res.json({ ok: false, msg: '0-9 mein se number daalo' });
  const settings = await getSettings();
  const round = await getCurrentRound(settings);
  if (!round || round.status === 'result') return res.json({ ok: false, msg: 'Round result ke liye ready nahi' });
  const mult = settings.multiplier || 9;
  const updatedBets = (round.bets || []).map(b => {
    if (b.status === 'approved') { b.won = b.number === num; b.winAmount = b.won ? b.amount * mult : 0; }
    return b;
  });
  const winners = updatedBets.filter(b => b.won && b.status === 'approved');
  for (const w of winners) { await db.collection('users').updateOne({ code: w.userCode }, { $inc: { coins: w.winAmount } }); }
  await db.collection('rounds').updateOne({ id: round.id }, { $set: { status: 'result', winNum: num, resultAt: Date.now(), bets: updatedBets } });
  settings.currentRoundId = null;
  await saveSettings(settings);
  await secLog('ROUND_RESULT', { winNum: num, winners: winners.length });
  res.json({ ok: true, winNum: num, winners: winners.map(w => ({ name: w.userName, code: w.userCode, coins: w.winAmount })) });
});

// ─── ADMIN: COINS ─────────────────────────────────────────
app.get('/admin/coins', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  res.json({ ok: true, requests: await db.collection('coinRequests').find().sort({ createdAt: -1 }).toArray() });
});

app.post('/admin/coins/approve', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body;
  const cr = await db.collection('coinRequests').findOne({ id: reqId });
  if (!cr || cr.status !== 'pending') return res.json({ ok: false, msg: cr ? 'Already processed' : 'Request nahi mili' });
  await db.collection('users').updateOne({ code: cr.userCode }, { $inc: { coins: cr.coins } });
  await db.collection('coinRequests').updateOne({ id: reqId }, { $set: { status: 'approved', processedAt: Date.now() } });
  await secLog('COIN_APPROVED', { code: cr.userCode, utr: cr.utr, coins: cr.coins });
  const user = await db.collection('users').findOne({ code: cr.userCode });
  res.json({ ok: true, coins: user.coins });
});

app.post('/admin/coins/reject', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId, blockUTR } = req.body;
  const cr = await db.collection('coinRequests').findOne({ id: reqId });
  if (!cr) return res.json({ ok: false, msg: 'Request nahi mili' });
  await db.collection('coinRequests').updateOne({ id: reqId }, { $set: { status: 'rejected', processedAt: Date.now() } });
  if (blockUTR) { const s = await getSettings(); s.blockedUTRs = [...(s.blockedUTRs || []), cr.utr]; await saveSettings(s); }
  await secLog('COIN_REJECTED', { code: cr.userCode, utr: cr.utr, blocked: blockUTR || false });
  res.json({ ok: true });
});

// ─── ADMIN: WITHDRAW ──────────────────────────────────────
app.get('/admin/withdraw', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  res.json({ ok: true, requests: await db.collection('withdrawRequests').find().sort({ createdAt: -1 }).toArray() });
});

app.post('/admin/withdraw/done', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body;
  const wr = await db.collection('withdrawRequests').findOne({ id: reqId });
  if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
  await db.collection('withdrawRequests').updateOne({ id: reqId }, { $set: { status: 'paid', paidAt: Date.now() } });
  await secLog('WITHDRAW_PAID', { code: wr.userCode, coins: wr.coins });
  res.json({ ok: true });
});

app.post('/admin/withdraw/reject', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body;
  const wr = await db.collection('withdrawRequests').findOne({ id: reqId });
  if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
  await db.collection('users').updateOne({ code: wr.userCode }, { $inc: { coins: wr.coins } });
  await db.collection('withdrawRequests').updateOne({ id: reqId }, { $set: { status: 'rejected', processedAt: Date.now() } });
  await secLog('WITHDRAW_REJECTED', { code: wr.userCode, coins: wr.coins });
  res.json({ ok: true });
});

// ─── ADMIN: USERS ─────────────────────────────────────────
app.post('/admin/user', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { name } = req.body;
  const code = genCode();
  await db.collection('users').insertOne({ code, name: name || 'User', createdAt: Date.now(), deviceId: null, coins: 0, banned: false });
  res.json({ ok: true, code, name: name || 'User' });
});

app.delete('/admin/user/:code', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  await db.collection('users').deleteOne({ code: req.params.code });
  res.json({ ok: true });
});

app.post('/admin/user/resetdevice', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code } = req.body;
  await db.collection('users').updateOne({ code }, { $set: { deviceId: null } });
  res.json({ ok: true });
});

app.post('/admin/user/coins', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code, coins } = req.body;
  const c = Math.max(0, parseInt(coins) || 0);
  await db.collection('users').updateOne({ code }, { $set: { coins: c } });
  res.json({ ok: true, coins: c });
});

app.post('/admin/user/ban', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code, blockDevice } = req.body;
  const user = await db.collection('users').findOne({ code });
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  await db.collection('users').updateOne({ code }, { $set: { banned: true, bannedAt: Date.now() } });
  if (blockDevice && user.deviceId) { const s = await getSettings(); s.blockedDevices = [...(s.blockedDevices || []), user.deviceId]; await saveSettings(s); }
  await secLog('USER_BANNED', { code, blockDevice: blockDevice || false });
  res.json({ ok: true });
});

app.post('/admin/user/unban', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code } = req.body;
  await db.collection('users').updateOne({ code }, { $set: { banned: false }, $unset: { bannedAt: '' } });
  await secLog('USER_UNBANNED', { code });
  res.json({ ok: true });
});

// ─── ADMIN: SETTINGS ──────────────────────────────────────
app.post('/admin/settings', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const settings = await getSettings();
  const { upiId, upiName, minBet, maxBet, multiplier, tgLink, minWithdraw, coinRate, maxDailyCoins } = req.body;
  if (upiId !== undefined) settings.upiId = upiId;
  if (upiName !== undefined) settings.upiName = upiName;
  if (minBet !== undefined && minBet !== '') settings.minBet = parseInt(minBet);
  if (maxBet !== undefined && maxBet !== '') settings.maxBet = parseInt(maxBet);
  if (multiplier !== undefined && multiplier !== '') settings.multiplier = parseInt(multiplier);
  if (tgLink !== undefined) settings.tgLink = tgLink;
  if (minWithdraw !== undefined && minWithdraw !== '') settings.minWithdraw = parseInt(minWithdraw);
  if (coinRate !== undefined && coinRate !== '') settings.coinRate = parseFloat(coinRate);
  if (maxDailyCoins !== undefined && maxDailyCoins !== '') settings.maxDailyCoins = parseInt(maxDailyCoins);
  await saveSettings(settings);
  res.json({ ok: true, settings });
});

// ─── ADMIN: SECURITY LOG ──────────────────────────────────
app.get('/admin/seclog', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const log = await db.collection('securityLog').find().sort({ at: -1 }).limit(200).toArray();
  res.json({ ok: true, log });
});

// ─── ADMIN: HISTORY ───────────────────────────────────────
app.get('/admin/history', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const history = await db.collection('rounds').find({ status: 'result' }).sort({ resultAt: -1 }).toArray();
  res.json({ ok: true, history });
});

app.delete('/admin/history/:roundId', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const r = await db.collection('rounds').deleteOne({ id: req.params.roundId });
  res.json({ ok: r.deletedCount > 0 });
});

app.delete('/admin/history', async (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  await db.collection('rounds').deleteMany({ status: 'result' });
  res.json({ ok: true });
});

// ─── HEALTH ───────────────────────────────────────────────
app.get('/health', async (req, res) => {
  const users = db ? await db.collection('users').countDocuments() : 0;
  res.json({ ok: true, db: 'mongodb', users });
});

// ─── START ────────────────────────────────────────────────
connectDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => console.log('Server on port ' + PORT));
}).catch(e => {
  console.error('DB connect failed:', e.message);
  process.exit(1);
});  return s;
}
function getCurrentRound(d) {
  if (!d.currentRoundId) return null;
  return d.rounds.find(r => r.id === d.currentRoundId) || null;
}
function ensureArrays(d) {
  if (!d.withdrawRequests) d.withdrawRequests = [];
  if (!d.coinRequests) d.coinRequests = [];
  if (!d.blockedDevices) d.blockedDevices = [];
  if (!d.blockedUTRs) d.blockedUTRs = [];
  if (!d.securityLog) d.securityLog = [];
  if (!d.settings.minWithdraw) d.settings.minWithdraw = 300;
  if (!d.settings.coinRate) d.settings.coinRate = 1;
  if (!d.settings.maxDailyCoins) d.settings.maxDailyCoins = 50000;
}

// ─── SECURITY LOG ─────────────────────────────────────────
function secLog(d, type, data) {
  if (!d.securityLog) d.securityLog = [];
  d.securityLog.unshift({ type, data, at: Date.now() });
  if (d.securityLog.length > 500) d.securityLog = d.securityLog.slice(0, 500);
}

// Get IP from request
function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
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

// ─── RATE LIMITING (in-memory) ────────────────────────────
const rateLimiter = {};
function checkRate(key, limit, windowMs) {
  const now = Date.now();
  if (!rateLimiter[key]) rateLimiter[key] = [];
  rateLimiter[key] = rateLimiter[key].filter(t => now - t < windowMs);
  if (rateLimiter[key].length >= limit) return false;
  rateLimiter[key].push(now);
  return true;
}

// ─── LOGIN ────────────────────────────────────────────────
app.post('/login', (req, res) => {
  const { code, deviceId } = req.body;
  const ip = getIP(req);
  if (!code) return res.json({ ok: false, msg: 'Code daalo' });
  const d = load(); ensureArrays(d);

  // Rate limit: 10 login attempts per IP per minute
  if (!checkRate('login:'+ip, 10, 60000)) {
    secLog(d, 'RATE_LIMIT', { ip, code: code.toUpperCase(), action: 'login' });
    save(d);
    return res.json({ ok: false, msg: 'Bahut zyada attempts. 1 minute baad try karo.' });
  }

  const user = d.users.find(u => u.code === code.trim().toUpperCase());
  if (!user) {
    secLog(d, 'LOGIN_FAIL', { ip, code: code.trim().toUpperCase() });
    save(d);
    return res.json({ ok: false, msg: 'Galat code — Telegram se lo: @Winx1010' });
  }

  // Check blocked device
  if (deviceId && d.blockedDevices.includes(deviceId)) {
    secLog(d, 'BLOCKED_DEVICE_LOGIN', { ip, code: user.code, deviceId });
    save(d);
    return res.json({ ok: false, msg: 'Yeh device block hai. Admin se contact karo.' });
  }

  // Check if user is banned
  if (user.banned) {
    secLog(d, 'BANNED_USER_LOGIN', { ip, code: user.code });
    save(d);
    return res.json({ ok: false, msg: 'Aapka account suspend hai. Admin se contact karo.' });
  }

  if (!user.deviceId && deviceId) {
    user.deviceId = deviceId;
    user.firstLoginAt = user.firstLoginAt || Date.now();
    user.lastLoginAt = Date.now();
    user.lastLoginIP = ip;
    save(d);
  } else if (user.deviceId && deviceId && user.deviceId !== deviceId) {
    secLog(d, 'DEVICE_MISMATCH', { ip, code: user.code, savedDevice: user.deviceId, newDevice: deviceId });
    save(d);
    return res.json({ ok: false, msg: 'Yeh code doosre phone pe use ho chuka hai' });
  } else {
    user.lastLoginAt = Date.now();
    user.lastLoginIP = ip;
    save(d);
  }

  if (user.coins === undefined) user.coins = 0;
  return res.json({ ok: true, user: { code: user.code, name: user.name, coins: user.coins||0 }, settings: d.settings });
});

app.post('/verify', (req, res) => {
  const { code } = req.body;
  if (!code) return res.json({ ok: false });
  const d = load(); ensureArrays(d);
  const user = d.users.find(u => u.code === code.trim().toUpperCase());
  if (!user || user.banned) return res.json({ ok: false, msg: 'Session expire — dobara login karo' });
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

// ─── MY HISTORY ──────────────────────────────────────────
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
      return { roundId:r.id, resultAt:r.resultAt, winNum:r.winNum, myNumber:bet.number, myAmount:bet.amount, won:bet.won, winAmount:bet.winAmount||0, status:bet.status };
    })
    .filter(Boolean).reverse().slice(0, 50);
  return res.json({ ok: true, history });
});

// ─── PLACE BET ───────────────────────────────────────────
app.post('/bet', (req, res) => {
  const { code, number, amount } = req.body;
  const ip = getIP(req);
  if (!code || number === undefined || !amount) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = load(); ensureArrays(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });
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
  user.coins = (user.coins||0) - amt;
  if (!round.bets) round.bets = [];
  const bet = { id:uid(), userCode:cleanCode, userName:user.name, number:num, amount:amt, status:'approved', placedAt:Date.now(), ip, won:null, winAmount:null };
  round.bets.push(bet);
  save(d);
  return res.json({ ok: true, bet: { id:bet.id, number:num, amount:amt, status:'approved' }, coins: user.coins });
});

// ─── COIN PURCHASE REQUEST ────────────────────────────────
app.post('/coins/buy', (req, res) => {
  const { code, utr, amount } = req.body;
  const ip = getIP(req);
  if (!code||!utr||!amount) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = load(); ensureArrays(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });

  // Rate limit: 5 coin requests per hour per user
  if (!checkRate('coinbuy:'+cleanCode, 5, 3600000)) {
    secLog(d, 'RATE_LIMIT', { ip, code: cleanCode, action: 'coins/buy' });
    save(d);
    return res.json({ ok: false, msg: 'Bahut zyada requests. 1 ghante mein max 5 requests.' });
  }

  const cleanUTR = utr.toString().trim().replace(/\s/g,'');
  if (!/^\d{6,20}$/.test(cleanUTR)) return res.json({ ok: false, msg: 'UTR sirf numbers (6-20 digit)' });

  // Block if UTR is in blockedUTRs
  if (d.blockedUTRs.includes(cleanUTR)) {
    secLog(d, 'BLOCKED_UTR_ATTEMPT', { ip, code: cleanCode, utr: cleanUTR });
    save(d);
    return res.json({ ok: false, msg: 'Yeh UTR permanently block hai.' });
  }

  // Check duplicate UTR across all coin requests
  const allUTRs = d.coinRequests.map(r=>r.utr);
  if (allUTRs.includes(cleanUTR)) {
    secLog(d, 'DUPLICATE_UTR', { ip, code: cleanCode, utr: cleanUTR });
    save(d);
    return res.json({ ok: false, msg: 'Yeh UTR pehle use ho chuka hai' });
  }

  const amt = parseInt(amount);
  if (isNaN(amt)||amt<10) return res.json({ ok: false, msg: 'Minimum ₹10 ka coin kharido' });

  // Daily limit check
  const todayStart = new Date(); todayStart.setHours(0,0,0,0);
  const todayCoins = d.coinRequests
    .filter(r => r.userCode===cleanCode && r.status==='approved' && r.createdAt >= todayStart.getTime())
    .reduce((s,r) => s+r.coins, 0);
  const maxDaily = d.settings.maxDailyCoins || 50000;
  const coinsToAdd = Math.floor(amt*(d.settings.coinRate||1));
  if (todayCoins + coinsToAdd > maxDaily) {
    secLog(d, 'DAILY_LIMIT', { ip, code: cleanCode, attempted: coinsToAdd, todayTotal: todayCoins });
    save(d);
    return res.json({ ok: false, msg: `Aaj ki daily limit ${maxDaily} coins hai. Kal try karo.` });
  }

  const req_obj = {
    id: uid(), userCode: cleanCode, userName: user.name,
    utr: cleanUTR, amount: amt, coins: coinsToAdd,
    status: 'pending', createdAt: Date.now(), ip
  };
  d.coinRequests.push(req_obj);
  secLog(d, 'COIN_REQUEST', { ip, code: cleanCode, utr: cleanUTR, amount: amt, coins: coinsToAdd });
  save(d);
  return res.json({ ok: true, msg: 'Request bhej di! Admin approve karega jald.' });
});

// ─── WITHDRAW REQUEST ─────────────────────────────────────
app.post('/withdraw', (req, res) => {
  const { code, coins, upiId } = req.body;
  const ip = getIP(req);
  if (!code||!coins||!upiId) return res.json({ ok: false, msg: 'Saari details daalo' });
  const d = load(); ensureArrays(d);
  const cleanCode = code.trim().toUpperCase();
  const user = d.users.find(u => u.code === cleanCode);
  if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });

  // Rate limit: 3 withdraw requests per hour
  if (!checkRate('withdraw:'+cleanCode, 3, 3600000)) {
    secLog(d, 'RATE_LIMIT', { ip, code: cleanCode, action: 'withdraw' });
    save(d);
    return res.json({ ok: false, msg: 'Bahut zyada withdraw requests. 1 ghante mein max 3.' });
  }

  const c = parseInt(coins);
  const minW = d.settings.minWithdraw || 300;
  if (isNaN(c)||c<minW) return res.json({ ok: false, msg: `Minimum ${minW} coins withdraw kar sakte ho` });
  if ((user.coins||0) < c) return res.json({ ok: false, msg: `Aapke paas sirf ${user.coins||0} coins hain` });

  // Fraud check: total withdrawn vs total bought
  const totalBought = d.coinRequests.filter(r=>r.userCode===cleanCode&&r.status==='approved').reduce((s,r)=>s+r.coins,0);
  const totalWon = d.rounds.flatMap(r=>r.bets||[]).filter(b=>b.userCode===cleanCode&&b.won).reduce((s,b)=>s+(b.winAmount||0),0);
  const totalWithdrawn = d.withdrawRequests.filter(r=>r.userCode===cleanCode&&r.status==='paid').reduce((s,r)=>s+r.coins,0);
  const maxCanWithdraw = totalBought + totalWon - totalWithdrawn;
  if (c > maxCanWithdraw + 1) {
    secLog(d, 'WITHDRAW_FRAUD_ATTEMPT', { ip, code: cleanCode, attempted: c, maxAllowed: maxCanWithdraw, bought: totalBought, won: totalWon, withdrawn: totalWithdrawn });
    save(d);
    return res.json({ ok: false, msg: 'Invalid withdraw amount. Admin se contact karo.' });
  }

  const cleanUpi = upiId.toString().trim();
  if (!cleanUpi) return res.json({ ok: false, msg: 'UPI ID daalo' });
  user.coins = (user.coins||0) - c;
  const req_obj = { id:uid(), userCode:cleanCode, userName:user.name, coins:c, upiId:cleanUpi, status:'pending', createdAt:Date.now(), ip };
  d.withdrawRequests.push(req_obj);
  secLog(d, 'WITHDRAW_REQUEST', { ip, code: cleanCode, coins: c, upiId: cleanUpi });
  save(d);
  return res.json({ ok: true, msg: `${c} coins withdraw request bhej di! Admin jald process karega.`, coins: user.coins });
});

// ─── ADMIN: USER PROFILE (full intelligence) ──────────────
app.get('/admin/user/:code', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); ensureArrays(d);
  const code = req.params.code.toUpperCase();
  const user = d.users.find(u => u.code === code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });

  // All coin requests
  const coinReqs = d.coinRequests.filter(r => r.userCode === code);
  const totalBought = coinReqs.filter(r=>r.status==='approved').reduce((s,r)=>s+r.coins,0);
  const totalSpentReal = coinReqs.filter(r=>r.status==='approved').reduce((s,r)=>s+r.amount,0);
  const pendingCoinReqs = coinReqs.filter(r=>r.status==='pending').length;
  const rejectedCoinReqs = coinReqs.filter(r=>r.status==='rejected').length;

  // All withdraw requests
  const wdReqs = d.withdrawRequests.filter(r => r.userCode === code);
  const totalWithdrawn = wdReqs.filter(r=>r.status==='paid').reduce((s,r)=>s+r.coins,0);
  const pendingWd = wdReqs.filter(r=>r.status==='pending').length;
  const rejectedWd = wdReqs.filter(r=>r.status==='rejected').length;

  // All bets
  const allBets = d.rounds.flatMap(r => {
    const bet = (r.bets||[]).find(b=>b.userCode===code);
    if (!bet) return [];
    return [{ ...bet, roundWinNum: r.winNum, resultAt: r.resultAt, roundId: r.id }];
  });
  const approvedBets = allBets.filter(b=>b.status==='approved');
  const totalBetCoins = approvedBets.reduce((s,b)=>s+b.amount,0);
  const totalWonCoins = approvedBets.filter(b=>b.won).reduce((s,b)=>s+(b.winAmount||0),0);
  const totalLostCoins = approvedBets.filter(b=>b.won===false).reduce((s,b)=>s+b.amount,0);
  const winCount = approvedBets.filter(b=>b.won).length;
  const lossCount = approvedBets.filter(b=>b.won===false).length;

  // Net position
  const netCoins = totalBought + totalWonCoins - totalLostCoins - totalWithdrawn;
  const realMoneyIn = totalSpentReal;
  const realMoneyOut = totalWithdrawn; // 1 coin = 1 rupee by default

  // Fraud risk score (simple)
  let riskScore = 0;
  let riskReasons = [];
  if (rejectedCoinReqs > 2) { riskScore += 30; riskReasons.push('Multiple rejected coin requests'); }
  if (pendingCoinReqs > 3) { riskScore += 20; riskReasons.push('Many pending coin requests'); }
  const withdrawRatio = totalBought > 0 ? totalWithdrawn/totalBought : 0;
  if (withdrawRatio > 2) { riskScore += 40; riskReasons.push('Withdraw >> Bought (possible fraud)'); }
  if (totalWonCoins > totalBought * 5) { riskScore += 20; riskReasons.push('Very high win ratio'); }
  const secLogs = (d.securityLog||[]).filter(l=>l.data&&l.data.code===code);
  const fraudLogs = secLogs.filter(l=>['DUPLICATE_UTR','BLOCKED_UTR_ATTEMPT','WITHDRAW_FRAUD_ATTEMPT','DEVICE_MISMATCH'].includes(l.type));
  if (fraudLogs.length > 0) { riskScore += fraudLogs.length * 25; riskReasons.push(`${fraudLogs.length} security flags`); }

  return res.json({
    ok: true,
    user: {
      code: user.code, name: user.name, coins: user.coins||0,
      banned: user.banned||false, deviceId: user.deviceId||null,
      createdAt: user.createdAt, firstLoginAt: user.firstLoginAt,
      lastLoginAt: user.lastLoginAt, lastLoginIP: user.lastLoginIP
    },
    coins: {
      current: user.coins||0,
      totalBought, totalSpentReal,
      totalWithdrawn, totalBetCoins,
      totalWonCoins, totalLostCoins,
      netCoins,
      realMoneyIn, realMoneyOut,
      pendingCoinReqs, rejectedCoinReqs,
      pendingWd, rejectedWd
    },
    bets: { total: approvedBets.length, wins: winCount, losses: lossCount },
    coinHistory: coinReqs.slice().reverse().slice(0,20),
    withdrawHistory: wdReqs.slice().reverse().slice(0,20),
    betHistory: allBets.slice(-20).reverse(),
    securityFlags: fraudLogs,
    risk: { score: Math.min(riskScore, 100), reasons: riskReasons }
  });
});

// ─── ADMIN: SEARCH USERS ──────────────────────────────────
app.get('/admin/search', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const q = (req.query.q||'').toUpperCase().trim();
  if (!q) return res.json({ ok: true, results: [] });
  const d = load(); ensureArrays(d);
  const results = d.users
    .filter(u => u.code.includes(q) || (u.name||'').toUpperCase().includes(q))
    .slice(0, 20)
    .map(u => ({
      code: u.code, name: u.name, coins: u.coins||0,
      banned: u.banned||false, deviceId: u.deviceId||null,
      lastLoginAt: u.lastLoginAt
    }));
  return res.json({ ok: true, results });
});

// ─── ADMIN DATA ───────────────────────────────────────────
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

// ─── ROUND CONTROLS ───────────────────────────────────────
app.post('/admin/round/start', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  if (getCurrentRound(d)) return res.json({ ok: false, msg: 'Pehle current round finish karo' });
  const round = { id:uid(), status:'open', startedAt:Date.now(), closedAt:null, resultAt:null, winNum:null, bets:[] };
  d.rounds.push(round); d.currentRoundId = round.id;
  secLog(d, 'ROUND_START', { id: round.id });
  save(d); res.json({ ok: true, round });
});

app.post('/admin/round/close', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); const round = getCurrentRound(d);
  if (!round||round.status!=='open') return res.json({ ok: false, msg: 'Koi open round nahi' });
  round.status='closed'; round.closedAt=Date.now();
  secLog(d, 'ROUND_CLOSE', { id: round.id });
  save(d); res.json({ ok: true });
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
        const user = d.users.find(u=>u.code===b.userCode);
        if (user) { user.coins = (user.coins||0) + b.winAmount; winners.push({ name:b.userName, code:b.userCode, coins:b.winAmount }); }
      }
    }
  });
  d.currentRoundId=null;
  secLog(d, 'ROUND_RESULT', { winNum: num, winners: winners.length });
  save(d); res.json({ ok:true, winNum:num, winners });
});

// ─── COIN REQUESTS ────────────────────────────────────────
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
  secLog(d, 'COIN_APPROVED', { code: cr.userCode, utr: cr.utr, coins: cr.coins });
  save(d); res.json({ ok: true, coins: user.coins });
});

app.post('/admin/coins/reject', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId, blockUTR } = req.body; const d = load(); ensureArrays(d);
  const cr = d.coinRequests.find(r=>r.id===reqId);
  if (!cr) return res.json({ ok: false, msg: 'Request nahi mili' });
  cr.status = 'rejected'; cr.processedAt = Date.now();
  if (blockUTR && !d.blockedUTRs.includes(cr.utr)) d.blockedUTRs.push(cr.utr);
  secLog(d, 'COIN_REJECTED', { code: cr.userCode, utr: cr.utr, blocked: blockUTR||false });
  save(d); res.json({ ok: true });
});

// ─── WITHDRAW REQUESTS ────────────────────────────────────
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
  secLog(d, 'WITHDRAW_PAID', { code: wr.userCode, coins: wr.coins, upiId: wr.upiId });
  save(d); res.json({ ok: true });
});

app.post('/admin/withdraw/reject', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { reqId } = req.body; const d = load(); ensureArrays(d);
  const wr = d.withdrawRequests.find(r=>r.id===reqId);
  if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
  const user = d.users.find(u=>u.code===wr.userCode);
  if (user) user.coins = (user.coins||0) + wr.coins;
  wr.status = 'rejected'; wr.processedAt = Date.now();
  secLog(d, 'WITHDRAW_REJECTED', { code: wr.userCode, coins: wr.coins });
  save(d); res.json({ ok: true });
});

// ─── USER MANAGEMENT ──────────────────────────────────────
app.post('/admin/user', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { name } = req.body; const d = load(); const code = genCode();
  d.users.push({ code, name:name||'User', createdAt:Date.now(), deviceId:null, coins:0, banned:false });
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
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  user.deviceId=null; save(d); res.json({ ok: true });
});

app.post('/admin/user/coins', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code, coins } = req.body; const d = load();
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  user.coins = Math.max(0, parseInt(coins)||0);
  save(d); res.json({ ok: true, coins: user.coins });
});

// Ban/unban user + optionally block device
app.post('/admin/user/ban', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code, blockDevice } = req.body; const d = load(); ensureArrays(d);
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  user.banned = true; user.bannedAt = Date.now();
  if (blockDevice && user.deviceId && !d.blockedDevices.includes(user.deviceId))
    d.blockedDevices.push(user.deviceId);
  secLog(d, 'USER_BANNED', { code, blockDevice: blockDevice||false, deviceId: user.deviceId });
  save(d); res.json({ ok: true });
});

app.post('/admin/user/unban', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { code } = req.body; const d = load(); ensureArrays(d);
  const user = d.users.find(u=>u.code===code);
  if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
  user.banned = false; delete user.bannedAt;
  secLog(d, 'USER_UNBANNED', { code });
  save(d); res.json({ ok: true });
});

// ─── SECURITY LOG ─────────────────────────────────────────
app.get('/admin/seclog', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load(); ensureArrays(d);
  res.json({ ok: true, log: (d.securityLog||[]).slice(0,200) });
});

// ─── SETTINGS ─────────────────────────────────────────────
app.post('/admin/settings', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const { upiId, upiName, minBet, maxBet, multiplier, tgLink, minWithdraw, coinRate, maxDailyCoins } = req.body;
  const d = load(); ensureArrays(d);
  if (upiId!==undefined) d.settings.upiId=upiId;
  if (upiName!==undefined) d.settings.upiName=upiName;
  if (minBet!==undefined&&minBet!=='') d.settings.minBet=parseInt(minBet);
  if (maxBet!==undefined&&maxBet!=='') d.settings.maxBet=parseInt(maxBet);
  if (multiplier!==undefined&&multiplier!=='') d.settings.multiplier=parseInt(multiplier);
  if (tgLink!==undefined) d.settings.tgLink=tgLink;
  if (minWithdraw!==undefined&&minWithdraw!=='') d.settings.minWithdraw=parseInt(minWithdraw);
  if (coinRate!==undefined&&coinRate!=='') d.settings.coinRate=parseFloat(coinRate);
  if (maxDailyCoins!==undefined&&maxDailyCoins!=='') d.settings.maxDailyCoins=parseInt(maxDailyCoins);
  save(d); res.json({ ok:true, settings:d.settings });
});

// ─── HISTORY ──────────────────────────────────────────────
app.get('/admin/history', (req, res) => {
  if (!auth(req)) return res.status(401).json({ ok: false });
  const d = load();
  res.json({ ok:true, history: d.rounds.filter(r=>r.status==='result').reverse() });
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
