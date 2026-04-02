const express = require('express');
const cors = require('cors');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'ADMIN2026';

// ─── FIREBASE INIT ────────────────────────────────────────
initializeApp({
  credential: cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY
      ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
      : undefined,
  }),
});
const firestore = getFirestore();
const DATA_DOC = firestore.collection('app').doc('data');

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

// ─── DEFAULT DATA STRUCTURE ───────────────────────────────
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
      tgLink: 'https://t.me/Winx1010',
      minWithdraw: 300,
      coinRate: 1,
      maxDailyCoins: 50000,
    },
  };
}

// ─── DB HELPERS ───────────────────────────────────────────
async function load() {
  try {
    const snap = await DATA_DOC.get();
    if (snap.exists) {
      const d = snap.data();
      if (!d.users) d.users = [];
      if (!d.rounds) d.rounds = [];
      if (!d.withdrawRequests) d.withdrawRequests = [];
      if (!d.coinRequests) d.coinRequests = [];
      if (!d.blockedDevices) d.blockedDevices = [];
      if (!d.blockedUTRs) d.blockedUTRs = [];
      if (!d.securityLog) d.securityLog = [];
      if (!d.settings) d.settings = defaultData().settings;
      if (!d.currentRoundId) d.currentRoundId = null;
      return d;
    }
  } catch (e) {
    console.error('Firestore load error:', e.message);
  }
  return defaultData();
}

async function save(d) {
  try {
    await DATA_DOC.set(d);
  } catch (e) {
    console.error('Firestore save error:', e.message);
  }
}

function auth(req) {
  return req.headers['x-pass'] === ADMIN_PASS;
}

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5).toUpperCase();
}

function genCode() {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  for (let i = 0; i < 8; i++) {
    if (i === 4) s += '-';
    s += c[Math.floor(Math.random() * c.length)];
  }
  return s;
}

function getCurrentRound(d) {
  if (!d.currentRoundId) return null;
  return d.rounds.find((r) => r.id === d.currentRoundId) || null;
}

function ensureArrays(d) {
  if (!d.withdrawRequests) d.withdrawRequests = [];
  if (!d.coinRequests) d.coinRequests = [];
  if (!d.blockedDevices) d.blockedDevices = [];
  if (!d.blockedUTRs) d.blockedUTRs = [];
  if (!d.securityLog) d.securityLog = [];
  if (!d.settings) d.settings = defaultData().settings;
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

function getIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

// ─── AUTO-CLOSE BETTING AT 40 MIN ─────────────────────────
setInterval(async () => {
  try {
    const d = await load();
    const round = getCurrentRound(d);
    if (!round || round.status !== 'open') return;
    if (Date.now() >= round.startedAt + 40 * 60 * 1000) {
      round.status = 'closed';
      round.closedAt = Date.now();
      await save(d);
      console.log('Auto-closed round', round.id);
    }
  } catch (e) {
    console.error('Auto-close error:', e.message);
  }
}, 15000);

// ─── RATE LIMITING (in-memory) ────────────────────────────
const rateLimiter = {};
function checkRate(key, limit, windowMs) {
  const now = Date.now();
  if (!rateLimiter[key]) rateLimiter[key] = [];
  rateLimiter[key] = rateLimiter[key].filter((t) => now - t < windowMs);
  if (rateLimiter[key].length >= limit) return false;
  rateLimiter[key].push(now);
  return true;
}

// ─── LOGIN ────────────────────────────────────────────────
app.post('/login', async (req, res) => {
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
  } catch (e) {
    console.error('/login error:', e.message);
    return res.json({ ok: false, msg: 'Server error' });
  }
});

app.post('/verify', async (req, res) => {
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
    const round = getCurrentRound(d);
    if (!round) return res.json({ ok: false, msg: 'Koi round nahi chala abhi' });
    if (round.status !== 'open') return res.json({ ok: false, msg: 'Betting band ho gayi' });
    const num = parseInt(number);
    if (isNaN(num) || num < 0 || num > 9)
      return res.json({ ok: false, msg: 'Number 0-9 ke beech hona chahiye' });
    const amt = parseInt(amount);
    if (isNaN(amt) || amt < d.settings.minBet || amt > d.settings.maxBet)
      return res.json({
        ok: false,
        msg: `Amount ${d.settings.minBet}-${d.settings.maxBet} coins ke beech hona chahiye`,
      });
    if ((user.coins || 0) < amt)
      return res.json({
        ok: false,
        msg: `Aapke paas sirf ${user.coins || 0} coins hain. Pehle coins kharido.`,
      });
    const existing = (round.bets || []).find(
      (b) => b.userCode === cleanCode && b.status !== 'rejected'
    );
    if (existing) return res.json({ ok: false, msg: 'Aapki bet pehle se hai is round mein' });
    user.coins = (user.coins || 0) - amt;
    if (!round.bets) round.bets = [];
    const bet = {
      id: uid(), userCode: cleanCode, userName: user.name,
      number: num, amount: amt, status: 'approved',
      placedAt: Date.now(), ip, won: null, winAmount: null,
    };
    round.bets.push(bet);
    await save(d);
    return res.json({
      ok: true,
      bet: { id: bet.id, number: num, amount: amt, status: 'approved' },
      coins: user.coins,
    });
  } catch (e) {
    console.error('/bet error:', e.message);
    return res.json({ ok: false, msg: 'Server error' });
  }
});

// ─── COIN PURCHASE REQUEST ────────────────────────────────
app.post('/coins/buy', async (req, res) => {
  try {
    const { code, utr, amount } = req.body;
    const ip = getIP(req);
    if (!code || !utr || !amount) return res.json({ ok: false, msg: 'Saari details daalo' });
    const d = await load();
    ensureArrays(d);
    const cleanCode = code.trim().toUpperCase();
    const user = d.users.find((u) => u.code === cleanCode);
    if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });

    if (!checkRate('coinbuy:' + cleanCode, 5, 3600000)) {
      secLog(d, 'RATE_LIMIT', { ip, code: cleanCode, action: 'coins/buy' });
      await save(d);
      return res.json({ ok: false, msg: 'Bahut zyada requests. 1 ghante mein max 5 requests.' });
    }

    const cleanUTR = utr.toString().trim().replace(/\s/g, '');
    if (!/^\d{6,20}$/.test(cleanUTR))
      return res.json({ ok: false, msg: 'UTR sirf numbers (6-20 digit)' });

    if (d.blockedUTRs.includes(cleanUTR)) {
      secLog(d, 'BLOCKED_UTR_ATTEMPT', { ip, code: cleanCode, utr: cleanUTR });
      await save(d);
      return res.json({ ok: false, msg: 'Yeh UTR permanently block hai.' });
    }

    const allUTRs = d.coinRequests.map((r) => r.utr);
    if (allUTRs.includes(cleanUTR)) {
      secLog(d, 'DUPLICATE_UTR', { ip, code: cleanCode, utr: cleanUTR });
      await save(d);
      return res.json({ ok: false, msg: 'Yeh UTR pehle use ho chuka hai' });
    }

    const amt = parseInt(amount);
    if (isNaN(amt) || amt < 10) return res.json({ ok: false, msg: 'Minimum ₹10 ka coin kharido' });

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const todayCoins = d.coinRequests
      .filter(
        (r) =>
          r.userCode === cleanCode &&
          r.status === 'approved' &&
          r.createdAt >= todayStart.getTime()
      )
      .reduce((s, r) => s + r.coins, 0);
    const maxDaily = d.settings.maxDailyCoins || 50000;
    const coinsToAdd = Math.floor(amt * (d.settings.coinRate || 1));
    if (todayCoins + coinsToAdd > maxDaily) {
      secLog(d, 'DAILY_LIMIT', { ip, code: cleanCode, attempted: coinsToAdd, todayTotal: todayCoins });
      await save(d);
      return res.json({ ok: false, msg: `Aaj ki daily limit ${maxDaily} coins hai. Kal try karo.` });
    }

    const req_obj = {
      id: uid(), userCode: cleanCode, userName: user.name,
      utr: cleanUTR, amount: amt, coins: coinsToAdd,
      status: 'pending', createdAt: Date.now(), ip,
    };
    d.coinRequests.push(req_obj);
    secLog(d, 'COIN_REQUEST', { ip, code: cleanCode, utr: cleanUTR, amount: amt, coins: coinsToAdd });
    await save(d);
    return res.json({ ok: true, msg: 'Request bhej di! Admin approve karega jald.' });
  } catch (e) {
    console.error('/coins/buy error:', e.message);
    return res.json({ ok: false, msg: 'Server error' });
  }
});

// ─── WITHDRAW REQUEST ─────────────────────────────────────
app.post('/withdraw', async (req, res) => {
  try {
    const { code, coins, upiId } = req.body;
    const ip = getIP(req);
    if (!code || !coins || !upiId) return res.json({ ok: false, msg: 'Saari details daalo' });
    const d = await load();
    ensureArrays(d);
    const cleanCode = code.trim().toUpperCase();
    const user = d.users.find((u) => u.code === cleanCode);
    if (!user || user.banned) return res.json({ ok: false, msg: 'Invalid code' });

    if (!checkRate('withdraw:' + cleanCode, 3, 3600000)) {
      secLog(d, 'RATE_LIMIT', { ip, code: cleanCode, action: 'withdraw' });
      await save(d);
      return res.json({ ok: false, msg: 'Bahut zyada withdraw requests. 1 ghante mein max 3.' });
    }

    const c = parseInt(coins);
    const minW = d.settings.minWithdraw || 300;
    if (isNaN(c) || c < minW)
      return res.json({ ok: false, msg: `Minimum ${minW} coins withdraw kar sakte ho` });
    if ((user.coins || 0) < c)
      return res.json({ ok: false, msg: `Aapke paas sirf ${user.coins || 0} coins hain` });

    const totalBought = d.coinRequests
      .filter((r) => r.userCode === cleanCode && r.status === 'approved')
      .reduce((s, r) => s + r.coins, 0);
    const totalWon = d.rounds
      .flatMap((r) => r.bets || [])
      .filter((b) => b.userCode === cleanCode && b.won)
      .reduce((s, b) => s + (b.winAmount || 0), 0);
    const totalWithdrawn = d.withdrawRequests
      .filter((r) => r.userCode === cleanCode && r.status === 'paid')
      .reduce((s, r) => s + r.coins, 0);
    const maxCanWithdraw = totalBought + totalWon - totalWithdrawn;
    if (c > maxCanWithdraw + 1) {
      secLog(d, 'WITHDRAW_FRAUD_ATTEMPT', {
        ip, code: cleanCode, attempted: c, maxAllowed: maxCanWithdraw,
        bought: totalBought, won: totalWon, withdrawn: totalWithdrawn,
      });
      await save(d);
      return res.json({ ok: false, msg: 'Invalid withdraw amount. Admin se contact karo.' });
    }

    const cleanUpi = upiId.toString().trim();
    if (!cleanUpi) return res.json({ ok: false, msg: 'UPI ID daalo' });
    user.coins = (user.coins || 0) - c;
    const req_obj = {
      id: uid(), userCode: cleanCode, userName: user.name,
      coins: c, upiId: cleanUpi, status: 'pending', createdAt: Date.now(), ip,
    };
    d.withdrawRequests.push(req_obj);
    secLog(d, 'WITHDRAW_REQUEST', { ip, code: cleanCode, coins: c, upiId: cleanUpi });
    await save(d);
    return res.json({
      ok: true,
      msg: `${c} coins withdraw request bhej di! Admin jald process karega.`,
      coins: user.coins,
    });
  } catch (e) {
    console.error('/withdraw error:', e.message);
    return res.json({ ok: false, msg: 'Server error' });
  }
});

// ─── ADMIN: USER PROFILE ──────────────────────────────────
app.get('/admin/user/:code', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const d = await load();
    ensureArrays(d);
    const code = req.params.code.toUpperCase();
    const user = d.users.find((u) => u.code === code);
    if (!user) return res.json({ ok: false, msg: 'User nahi mila' });

    const coinReqs = d.coinRequests.filter((r) => r.userCode === code);
    const totalBought = coinReqs.filter((r) => r.status === 'approved').reduce((s, r) => s + r.coins, 0);
    const totalSpentReal = coinReqs.filter((r) => r.status === 'approved').reduce((s, r) => s + r.amount, 0);
    const pendingCoinReqs = coinReqs.filter((r) => r.status === 'pending').length;
    const rejectedCoinReqs = coinReqs.filter((r) => r.status === 'rejected').length;

    const wdReqs = d.withdrawRequests.filter((r) => r.userCode === code);
    const totalWithdrawn = wdReqs.filter((r) => r.status === 'paid').reduce((s, r) => s + r.coins, 0);
    const pendingWd = wdReqs.filter((r) => r.status === 'pending').length;
    const rejectedWd = wdReqs.filter((r) => r.status === 'rejected').length;

    const allBets = d.rounds.flatMap((r) => {
      const bet = (r.bets || []).find((b) => b.userCode === code);
      if (!bet) return [];
      return [{ ...bet, roundWinNum: r.winNum, resultAt: r.resultAt, roundId: r.id }];
    });
    const approvedBets = allBets.filter((b) => b.status === 'approved');
    const totalBetCoins = approvedBets.reduce((s, b) => s + b.amount, 0);
    const totalWonCoins = approvedBets.filter((b) => b.won).reduce((s, b) => s + (b.winAmount || 0), 0);
    const totalLostCoins = approvedBets.filter((b) => b.won === false).reduce((s, b) => s + b.amount, 0);
    const winCount = approvedBets.filter((b) => b.won).length;
    const lossCount = approvedBets.filter((b) => b.won === false).length;

    const netCoins = totalBought + totalWonCoins - totalLostCoins - totalWithdrawn;
    const realMoneyIn = totalSpentReal;
    const realMoneyOut = totalWithdrawn;

    let riskScore = 0;
    let riskReasons = [];
    if (rejectedCoinReqs > 2) { riskScore += 30; riskReasons.push('Multiple rejected coin requests'); }
    if (pendingCoinReqs > 3) { riskScore += 20; riskReasons.push('Many pending coin requests'); }
    const withdrawRatio = totalBought > 0 ? totalWithdrawn / totalBought : 0;
    if (withdrawRatio > 2) { riskScore += 40; riskReasons.push('Withdraw >> Bought (possible fraud)'); }
    if (totalWonCoins > totalBought * 5) { riskScore += 20; riskReasons.push('Very high win ratio'); }
    const secLogs = (d.securityLog || []).filter((l) => l.data && l.data.code === code);
    const fraudLogs = secLogs.filter((l) =>
      ['DUPLICATE_UTR', 'BLOCKED_UTR_ATTEMPT', 'WITHDRAW_FRAUD_ATTEMPT', 'DEVICE_MISMATCH'].includes(l.type)
    );
    if (fraudLogs.length > 0) {
      riskScore += fraudLogs.length * 25;
      riskReasons.push(`${fraudLogs.length} security flags`);
    }

    return res.json({
      ok: true,
      user: {
        code: user.code, name: user.name, coins: user.coins || 0,
        banned: user.banned || false, deviceId: user.deviceId || null,
        createdAt: user.createdAt, firstLoginAt: user.firstLoginAt,
        lastLoginAt: user.lastLoginAt, lastLoginIP: user.lastLoginIP,
      },
      coins: {
        current: user.coins || 0, totalBought, totalSpentReal,
        totalWithdrawn, totalBetCoins, totalWonCoins, totalLostCoins,
        netCoins, realMoneyIn, realMoneyOut,
        pendingCoinReqs, rejectedCoinReqs, pendingWd, rejectedWd,
      },
      bets: { total: approvedBets.length, wins: winCount, losses: lossCount },
      coinHistory: coinReqs.slice().reverse().slice(0, 20),
      withdrawHistory: wdReqs.slice().reverse().slice(0, 20),
      betHistory: allBets.slice(-20).reverse(),
      securityFlags: fraudLogs,
      risk: { score: Math.min(riskScore, 100), reasons: riskReasons },
    });
  } catch (e) {
    console.error('/admin/user/:code error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

// ─── ADMIN: SEARCH USERS ──────────────────────────────────
app.get('/admin/search', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const q = (req.query.q || '').toUpperCase().trim();
    if (!q) return res.json({ ok: true, results: [] });
    const d = await load();
    ensureArrays(d);
    const results = d.users
      .filter((u) => u.code.includes(q) || (u.name || '').toUpperCase().includes(q))
      .slice(0, 20)
      .map((u) => ({
        code: u.code, name: u.name, coins: u.coins || 0,
        banned: u.banned || false, deviceId: u.deviceId || null,
        lastLoginAt: u.lastLoginAt,
      }));
    return res.json({ ok: true, results });
  } catch (e) {
    console.error('/admin/search error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

// ─── ADMIN DATA ───────────────────────────────────────────
app.get('/admin/data', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const d = await load();
    ensureArrays(d);
    const round = getCurrentRound(d);
    let numStats = null;
    if (round && round.bets) {
      numStats = {};
      for (let i = 0; i <= 9; i++) numStats[i] = { count: 0, total: 0, bets: [] };
      round.bets
        .filter((b) => b.status === 'approved')
        .forEach((b) => {
          numStats[b.number].count++;
          numStats[b.number].total += b.amount;
          numStats[b.number].bets.push({ name: b.userName, code: b.userCode, amount: b.amount });
        });
    }
    const ri = round
      ? { ...round, betEndsAt: round.startedAt + 40 * 60 * 1000, roundEndsAt: round.startedAt + 60 * 60 * 1000 }
      : null;
    const pendingCoins = d.coinRequests.filter((r) => r.status === 'pending').length;
    const pendingWithdraw = d.withdrawRequests.filter((r) => r.status === 'pending').length;
    return res.json({
      ok: true, users: d.users, round: ri, numStats, settings: d.settings,
      pendingCoins, pendingWithdraw,
      stats: {
        totalUsers: d.users.length,
        totalRounds: d.rounds.filter((r) => r.status === 'result').length,
        currentBets: round ? (round.bets || []).filter((b) => b.status === 'approved').length : 0,
        currentAmount: round
          ? (round.bets || []).filter((b) => b.status === 'approved').reduce((s, b) => s + b.amount, 0)
          : 0,
      },
    });
  } catch (e) {
    console.error('/admin/data error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

// ─── ROUND CONTROLS ───────────────────────────────────────
app.post('/admin/round/start', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const d = await load();
    if (getCurrentRound(d)) return res.json({ ok: false, msg: 'Pehle current round finish karo' });
    const round = {
      id: uid(), status: 'open', startedAt: Date.now(),
      closedAt: null, resultAt: null, winNum: null, bets: [],
    };
    d.rounds.push(round);
    d.currentRoundId = round.id;
    secLog(d, 'ROUND_START', { id: round.id });
    await save(d);
    res.json({ ok: true, round });
  } catch (e) {
    console.error('/admin/round/start error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post('/admin/round/close', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const d = await load();
    const round = getCurrentRound(d);
    if (!round || round.status !== 'open')
      return res.json({ ok: false, msg: 'Koi open round nahi' });
    round.status = 'closed';
    round.closedAt = Date.now();
    secLog(d, 'ROUND_CLOSE', { id: round.id });
    await save(d);
    res.json({ ok: true });
  } catch (e) {
    console.error('/admin/round/close error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post('/admin/round/result', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const { winNum } = req.body;
    const num = parseInt(winNum);
    if (isNaN(num) || num < 0 || num > 9)
      return res.json({ ok: false, msg: '0-9 mein se number daalo' });
    const d = await load();
    ensureArrays(d);
    const round = getCurrentRound(d);
    if (!round || round.status === 'result')
      return res.json({ ok: false, msg: 'Round result ke liye ready nahi' });
    const mult = d.settings.multiplier || 9;
    round.status = 'result';
    round.winNum = num;
    round.resultAt = Date.now();
    const winners = [];
    (round.bets || []).forEach((b) => {
      if (b.status === 'approved') {
        b.won = b.number === num;
        b.winAmount = b.won ? b.amount * mult : 0;
        if (b.won) {
          const user = d.users.find((u) => u.code === b.userCode);
          if (user) {
            user.coins = (user.coins || 0) + b.winAmount;
            winners.push({ name: b.userName, code: b.userCode, coins: b.winAmount });
          }
        }
      }
    });
    d.currentRoundId = null;
    secLog(d, 'ROUND_RESULT', { winNum: num, winners: winners.length });
    await save(d);
    res.json({ ok: true, winNum: num, winners });
  } catch (e) {
    console.error('/admin/round/result error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

// ─── COIN REQUESTS ────────────────────────────────────────
app.get('/admin/coins', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const d = await load();
    ensureArrays(d);
    res.json({ ok: true, requests: d.coinRequests.slice().reverse() });
  } catch (e) {
    console.error('/admin/coins error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post('/admin/coins/approve', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const { reqId } = req.body;
    const d = await load();
    ensureArrays(d);
    const cr = d.coinRequests.find((r) => r.id === reqId);
    if (!cr) return res.json({ ok: false, msg: 'Request nahi mili' });
    if (cr.status !== 'pending') return res.json({ ok: false, msg: 'Already processed' });
    const user = d.users.find((u) => u.code === cr.userCode);
    if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
    user.coins = (user.coins || 0) + cr.coins;
    cr.status = 'approved';
    cr.processedAt = Date.now();
    secLog(d, 'COIN_APPROVED', { code: cr.userCode, utr: cr.utr, coins: cr.coins });
    await save(d);
    res.json({ ok: true, coins: user.coins });
  } catch (e) {
    console.error('/admin/coins/approve error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post('/admin/coins/reject', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const { reqId, blockUTR } = req.body;
    const d = await load();
    ensureArrays(d);
    const cr = d.coinRequests.find((r) => r.id === reqId);
    if (!cr) return res.json({ ok: false, msg: 'Request nahi mili' });
    cr.status = 'rejected';
    cr.processedAt = Date.now();
    if (blockUTR && !d.blockedUTRs.includes(cr.utr)) d.blockedUTRs.push(cr.utr);
    secLog(d, 'COIN_REJECTED', { code: cr.userCode, utr: cr.utr, blocked: blockUTR || false });
    await save(d);
    res.json({ ok: true });
  } catch (e) {
    console.error('/admin/coins/reject error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

// ─── WITHDRAW REQUESTS ────────────────────────────────────
app.get('/admin/withdraw', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const d = await load();
    ensureArrays(d);
    res.json({ ok: true, requests: d.withdrawRequests.slice().reverse() });
  } catch (e) {
    console.error('/admin/withdraw error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post('/admin/withdraw/done', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const { reqId } = req.body;
    const d = await load();
    ensureArrays(d);
    const wr = d.withdrawRequests.find((r) => r.id === reqId);
    if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
    wr.status = 'paid';
    wr.paidAt = Date.now();
    secLog(d, 'WITHDRAW_PAID', { code: wr.userCode, coins: wr.coins, upiId: wr.upiId });
    await save(d);
    res.json({ ok: true });
  } catch (e) {
    console.error('/admin/withdraw/done error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post('/admin/withdraw/reject', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const { reqId } = req.body;
    const d = await load();
    ensureArrays(d);
    const wr = d.withdrawRequests.find((r) => r.id === reqId);
    if (!wr) return res.json({ ok: false, msg: 'Request nahi mili' });
    const user = d.users.find((u) => u.code === wr.userCode);
    if (user) user.coins = (user.coins || 0) + wr.coins;
    wr.status = 'rejected';
    wr.processedAt = Date.now();
    secLog(d, 'WITHDRAW_REJECTED', { code: wr.userCode, coins: wr.coins });
    await save(d);
    res.json({ ok: true });
  } catch (e) {
    console.error('/admin/withdraw/reject error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

// ─── USER MANAGEMENT ──────────────────────────────────────
app.post('/admin/user', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const { name } = req.body;
    const d = await load();
    const code = genCode();
    d.users.push({
      code, name: name || 'User', createdAt: Date.now(),
      deviceId: null, coins: 0, banned: false,
    });
    await save(d);
    res.json({ ok: true, code, name: name || 'User' });
  } catch (e) {
    console.error('/admin/user POST error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.delete('/admin/user/:code', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const d = await load();
    d.users = d.users.filter((u) => u.code !== req.params.code);
    await save(d);
    res.json({ ok: true });
  } catch (e) {
    console.error('/admin/user DELETE error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post('/admin/user/resetdevice', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const { code } = req.body;
    const d = await load();
    const user = d.users.find((u) => u.code === code);
    if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
    user.deviceId = null;
    await save(d);
    res.json({ ok: true });
  } catch (e) {
    console.error('/admin/user/resetdevice error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post('/admin/user/coins', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const { code, coins } = req.body;
    const d = await load();
    const user = d.users.find((u) => u.code === code);
    if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
    user.coins = Math.max(0, parseInt(coins) || 0);
    await save(d);
    res.json({ ok: true, coins: user.coins });
  } catch (e) {
    console.error('/admin/user/coins error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post('/admin/user/ban', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const { code, blockDevice } = req.body;
    const d = await load();
    ensureArrays(d);
    const user = d.users.find((u) => u.code === code);
    if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
    user.banned = true;
    user.bannedAt = Date.now();
    if (blockDevice && user.deviceId && !d.blockedDevices.includes(user.deviceId))
      d.blockedDevices.push(user.deviceId);
    secLog(d, 'USER_BANNED', { code, blockDevice: blockDevice || false, deviceId: user.deviceId });
    await save(d);
    res.json({ ok: true });
  } catch (e) {
    console.error('/admin/user/ban error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post('/admin/user/unban', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const { code } = req.body;
    const d = await load();
    ensureArrays(d);
    const user = d.users.find((u) => u.code === code);
    if (!user) return res.json({ ok: false, msg: 'User nahi mila' });
    user.banned = false;
    delete user.bannedAt;
    secLog(d, 'USER_UNBANNED', { code });
    await save(d);
    res.json({ ok: true });
  } catch (e) {
    console.error('/admin/user/unban error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

// ─── SECURITY LOG ─────────────────────────────────────────
app.get('/admin/seclog', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const d = await load();
    ensureArrays(d);
    res.json({ ok: true, log: (d.securityLog || []).slice(0, 200) });
  } catch (e) {
    console.error('/admin/seclog error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

// ─── SETTINGS ─────────────────────────────────────────────
app.post('/admin/settings', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const { upiId, upiName, minBet, maxBet, multiplier, tgLink, minWithdraw, coinRate, maxDailyCoins } = req.body;
    const d = await load();
    ensureArrays(d);
    if (upiId !== undefined) d.settings.upiId = upiId;
    if (upiName !== undefined) d.settings.upiName = upiName;
    if (minBet !== undefined && minBet !== '') d.settings.minBet = parseInt(minBet);
    if (maxBet !== undefined && maxBet !== '') d.settings.maxBet = parseInt(maxBet);
    if (multiplier !== undefined && multiplier !== '') d.settings.multiplier = parseInt(multiplier);
    if (tgLink !== undefined) d.settings.tgLink = tgLink;
    if (minWithdraw !== undefined && minWithdraw !== '') d.settings.minWithdraw = parseInt(minWithdraw);
    if (coinRate !== undefined && coinRate !== '') d.settings.coinRate = parseFloat(coinRate);
    if (maxDailyCoins !== undefined && maxDailyCoins !== '') d.settings.maxDailyCoins = parseInt(maxDailyCoins);
    await save(d);
    res.json({ ok: true, settings: d.settings });
  } catch (e) {
    console.error('/admin/settings error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

// ─── HISTORY ──────────────────────────────────────────────
app.get('/admin/history', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const d = await load();
    res.json({ ok: true, history: d.rounds.filter((r) => r.status === 'result').reverse() });
  } catch (e) {
    console.error('/admin/history error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.delete('/admin/history/:roundId', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const d = await load();
    const before = d.rounds.length;
    d.rounds = d.rounds.filter((r) => r.id !== req.params.roundId);
    if (d.rounds.length === before) return res.json({ ok: false, msg: 'Round nahi mila' });
    await save(d);
    res.json({ ok: true });
  } catch (e) {
    console.error('/admin/history/:roundId DELETE error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.delete('/admin/history', async (req, res) => {
  try {
    if (!auth(req)) return res.status(401).json({ ok: false });
    const d = await load();
    d.rounds = d.rounds.filter((r) => r.status !== 'result');
    await save(d);
    res.json({ ok: true });
  } catch (e) {
    console.error('/admin/history DELETE error:', e.message);
    return res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.listen(PORT, '0.0.0.0', () => console.log('Server running on port ' + PORT));
