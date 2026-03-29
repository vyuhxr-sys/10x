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
app.use(express.json({ limit: '50kb' }));

// ── Rate Limiter ──────────────────────────────────────────
const rl = {};
function rateLimit(ip, key, max, ms) {
  const k = ip + ':' + key, now = Date.now();
  if (!rl[k] || now - rl[k].s > ms) { rl[k] = { c: 1, s: now }; return false; }
  rl[k].c++;
  return rl[k].c > max;
}
setInterval(() => { const n = Date.now(); Object.keys(rl).forEach(k => { if (n - rl[k].s > 600000) delete rl[k]; }); }, 600000);
function getIP(req) { return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown'; }

// ── Security Log ──────────────────────────────────────────
function secLog(type, data) {
  const e = JSON.stringify({ t: new Date().toISOString(), type, ...data }) + '\n';
  try { fs.appendFileSync(LOG, e); } catch(e) {}
}

// ── DB ────────────────────────────────────────────────────
let saving = false;
function load() {
  try { if (fs.existsSync(DATA)) return JSON.parse(fs.readFileSync(DATA, 'utf8')); } catch(e) {}
  return { users:[], rounds:[], currentRoundId:null, withdrawRequests:[], coinRequests:[], blockedUTRs:[], blockedIPs:[],
    settings:{ upiId:'', upiName:'Admin', minBet:10, maxBet:5000, multiplier:9, tgLink:'https://t.me/Winx1010', minWithdraw:300, coinRate:1, maxCoinBuyPerDay:10000, maxWithdrawPerDay:5000 }
  };
}
function save(d) {
  if (saving) { setTimeout(() => save(d), 50); return; }
  saving = true;
  try { const t = DATA+'.tmp'; fs.writeFileSync(t, JSON.stringify(d,null,2)); fs.renameSync(t, DATA); }
  catch(e) { console.error('Save error', e); }
  finally { saving = false; }
}
function fix(d) {
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
  const c='ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let s='';
  for(let i=0;i<8;i++){if(i===4)s+='-';s+=c[Math.floor(Math.random()*c.length)];}
  return s;
}
function getRound(d) { return d.currentRoundId ? d.rounds.find(r=>r.id===d.currentRoundId)||null : null; }

// ── Helpers ───────────────────────────────────────────────
function usedUTRs(d) { return new Set(d.coinRequests.map(r=>r.utr)); }
function coinsBoughtToday(d, code) {
  const t = new Date(); t.setHours(0,0,0,0);
  return d.coinRequests.filter(r=>r.userCode===code&&r.status!=='rejected'&&r.createdAt>=t.getTime()).reduce((s,r)=>s+r.coins,0);
}
function withdrawnToday(d, code) {
  const t = new Date(); t.setHours(0,0,0,0);
  return d.withdrawRequests.filter(r=>r.userCode===code&&r.status!=='rejected'&&r.createdAt>=t.getTime()).reduce((s,r)=>s+r.coins,0);
}
function userAudit(d, code) {
  const cb=d.coinRequests.filter(r=>r.userCode===code), wr=d.withdrawRequests.filter(r=>r.userCode===code);
  const bets=d.rounds.flatMap(r=>(r.bets||[]).filter(b=>b.userCode===code));
  return {
    totalBought: cb.filter(r=>r.status==='approved').reduce((s,r)=>s+r.coins,0),
    totalWon: bets.filter(b=>b.won).reduce((s,b)=>s+(b.winAmount||0),0),
    totalBet: bets.filter(b=>b.status==='approved').reduce((s,b)=>s+b.amount,0),
    totalWithdrawn: wr.filter(r=>r.status!=='rejected').reduce((s,r)=>s+r.coins,0),
    buys: cb.length, withdrawals: wr.length, bets: bets.length
  };
}

// Auto-close at 40 min
setInterval(()=>{
  try {
    const d=load(); const r=getRound(d);
    if(!r||r.status!=='open') return;
    if(Date.now()>=r.startedAt+40*60*1000){r.status='closed';r.closedAt=Date.now();save(d);}
  }catch(e){}
},15000);

// ── IP Block Middleware ───────────────────────────────────
app.use((req,res,next)=>{
  const ip=getIP(req), d=load();
  if((d.blockedIPs||[]).includes(ip)){secLog('BLOCKED_IP',{ip,path:req.path});return res.status(403).json({ok:false,msg:'Access denied'});}
  next();
});

// ══ PUBLIC ═══════════════════════════════════════════════

app.post('/login',(req,res)=>{
  const ip=getIP(req);
  if(rateLimit(ip,'login',10,60000)) return res.json({ok:false,msg:'Bahut zyada attempts. 1 min ruko.'});
  const {code,deviceId}=req.body;
  if(!code||typeof code!=='string') return res.json({ok:false,msg:'Code daalo'});
  const d=load(); fix(d);
  const u=d.users.find(u=>u.code===code.trim().toUpperCase().substring(0,20));
  if(!u){secLog('LOGIN_FAIL',{ip,code});return res.json({ok:false,msg:'Galat code — Telegram se lo: @Winx1010'});}
  if(u.banned) return res.json({ok:false,msg:'Account suspended. Admin se contact karo.'});
  const dev=deviceId?String(deviceId).substring(0,100):null;
  if(!u.deviceId&&dev){u.deviceId=dev;save(d);}
  else if(u.deviceId&&dev&&u.deviceId!==dev){secLog('DEVICE_MISMATCH',{ip,code:u.code});return res.json({ok:false,msg:'Yeh code doosre phone pe use ho chuka hai.'});}
  if(u.coins===undefined){u.coins=0;save(d);}
  return res.json({ok:true,user:{code:u.code,name:u.name,coins:u.coins},settings:d.settings});
});

app.post('/verify',(req,res)=>{
  const {code}=req.body; if(!code) return res.json({ok:false});
  const d=load(); fix(d);
  const u=d.users.find(u=>u.code===code.trim().toUpperCase());
  if(!u||u.banned) return res.json({ok:false,msg:'Session expire — dobara login karo'});
  if(u.coins===undefined){u.coins=0;}
  return res.json({ok:true,user:{code:u.code,name:u.name,coins:u.coins},settings:d.settings});
});

app.get('/round',(req,res)=>{
  const d=load(); const r=getRound(d);
  if(!r) return res.json({ok:true,round:null,settings:d.settings});
  return res.json({ok:true,round:{id:r.id,status:r.status,startedAt:r.startedAt,betEndsAt:r.startedAt+40*60*1000,roundEndsAt:r.startedAt+60*60*1000,winNum:r.status==='result'?r.winNum:null},settings:d.settings});
});

app.post('/mybetStatus',(req,res)=>{
  const {code}=req.body; if(!code) return res.json({ok:false});
  const d=load(); fix(d);
  const clean=code.trim().toUpperCase();
  const u=d.users.find(u=>u.code===clean);
  if(!u) return res.json({ok:false});
  let r=getRound(d);
  if(!r){const done=d.rounds.filter(r=>r.status==='result');r=done.length?done[done.length-1]:null;}
  const coins=u.coins||0;
  if(!r) return res.json({ok:true,bet:null,round:null,settings:d.settings,coins});
  const bet=(r.bets||[]).find(b=>b.userCode===clean);
  const ri={id:r.id,status:r.status,startedAt:r.startedAt,betEndsAt:r.startedAt+40*60*1000,roundEndsAt:r.startedAt+60*60*1000,winNum:r.status==='result'?r.winNum:null};
  return res.json({ok:true,bet:bet||null,round:ri,settings:d.settings,coins});
});

app.post('/myhistory',(req,res)=>{
  const ip=getIP(req);
  if(rateLimit(ip,'hist',20,60000)) return res.json({ok:false});
  const {code}=req.body; if(!code) return res.json({ok:false});
  const d=load(); fix(d);
  const clean=code.trim().toUpperCase();
  const u=d.users.find(u=>u.code===clean);
  if(!u) return res.json({ok:false});
  const history=d.rounds.filter(r=>r.status==='result').map(r=>{
    const b=(r.bets||[]).find(b=>b.userCode===clean);
    if(!b||b.status==='rejected') return null;
    return {roundId:r.id,resultAt:r.resultAt,winNum:r.winNum,myNumber:b.number,myAmount:b.amount,won:b.won,winAmount:b.winAmount||0};
  }).filter(Boolean).reverse().slice(0,50);
  const coinTx=d.coinRequests.filter(r=>r.userCode===clean).slice(-30).reverse().map(r=>({type:'buy',amount:r.amount,coins:r.coins,status:r.status,createdAt:r.createdAt}));
  const withdrawTx=d.withdrawRequests.filter(r=>r.userCode===clean).slice(-30).reverse().map(r=>({type:'withdraw',coins:r.coins,upiId:r.upiId,status:r.status,createdAt:r.createdAt}));
  return res.json({ok:true,history,coinTx,withdrawTx,coins:u.coins||0});
});

app.post('/bet',(req,res)=>{
  const ip=getIP(req);
  if(rateLimit(ip,'bet',5,30000)) return res.json({ok:false,msg:'Thoda ruko.'});
  const {code,number,amount}=req.body;
  if(!code||number===undefined||!amount) return res.json({ok:false,msg:'Saari details daalo'});
  const d=load(); fix(d);
  const clean=code.trim().toUpperCase();
  const u=d.users.find(u=>u.code===clean);
  if(!u||u.banned) return res.json({ok:false,msg:'Invalid code'});
  const r=getRound(d);
  if(!r) return res.json({ok:false,msg:'Koi round nahi chala abhi'});
  if(r.status!=='open') return res.json({ok:false,msg:'Betting band ho gayi'});
  const num=parseInt(number);
  if(isNaN(num)||num<0||num>9) return res.json({ok:false,msg:'Number 0-9 ke beech'});
  const amt=parseInt(amount);
  if(isNaN(amt)||amt<d.settings.minBet||amt>d.settings.maxBet) return res.json({ok:false,msg:`Coins ${d.settings.minBet}–${d.settings.maxBet} ke beech hona chahiye`});
  if((u.coins||0)<amt) return res.json({ok:false,msg:`Coins kam hain (${u.coins||0}). Pehle coins kharido.`});
  if((r.bets||[]).find(b=>b.userCode===clean&&b.status!=='rejected')) return res.json({ok:false,msg:'Aapki bet pehle se hai'});
  u.coins=(u.coins||0)-amt;
  if(!r.bets) r.bets=[];
  const bet={id:uid(),userCode:clean,userName:u.name,number:num,amount:amt,status:'approved',placedAt:Date.now(),ip,won:null,winAmount:null};
  r.bets.push(bet); save(d);
  return res.json({ok:true,bet:{id:bet.id,number:num,amount:amt,status:'approved'},coins:u.coins});
});

app.post('/coins/buy',(req,res)=>{
  const ip=getIP(req);
  if(rateLimit(ip,'coinbuy',5,300000)) return res.json({ok:false,msg:'Bahut zyada requests. 5 min baad try karo.'});
  const {code,utr,amount}=req.body;
  if(!code||!utr||!amount) return res.json({ok:false,msg:'Saari details daalo'});
  const d=load(); fix(d);
  const clean=code.trim().toUpperCase();
  const u=d.users.find(u=>u.code===clean);
  if(!u||u.banned) return res.json({ok:false,msg:'Invalid code'});
  const cleanUTR=String(utr).trim().replace(/\s/g,'');
  if(!/^\d{6,25}$/.test(cleanUTR)) return res.json({ok:false,msg:'UTR sirf numbers hona chahiye (6-25 digit)'});
  if((d.blockedUTRs||[]).includes(cleanUTR)){secLog('BLOCKED_UTR',{ip,code:clean,utr:cleanUTR});return res.json({ok:false,msg:'Yeh UTR block hai. Admin se contact karo.'});}
  if(usedUTRs(d).has(cleanUTR)){secLog('DUPLICATE_UTR',{ip,code:clean,utr:cleanUTR});return res.json({ok:false,msg:'Yeh UTR pehle use ho chuka hai'});}
  const amt=parseInt(amount);
  if(isNaN(amt)||amt<10||amt>500000) return res.json({ok:false,msg:'Amount ₹10–₹5,00,000 ke beech'});
  const coins=Math.floor(amt*(d.settings.coinRate||1));
  const todayBought=coinsBoughtToday(d,clean);
  const maxPerDay=d.settings.maxCoinBuyPerDay||10000;
  if(todayBought+coins>maxPerDay) return res.json({ok:false,msg:`Aaj ki limit ${maxPerDay} coins. Kal dobara try karo.`});
  // Suspicious pattern: 5+ same-amount requests
  const recent=d.coinRequests.filter(r=>r.userCode===clean).slice(-5);
  if(recent.length>=5&&new Set(recent.map(r=>r.amount)).size===1){
    u.suspicious=(u.suspicious||0)+1;
    secLog('SUSPICIOUS_COINBUY',{ip,code:clean,utr:cleanUTR,amount:amt});
  }
  const req_obj={id:uid(),userCode:clean,userName:u.name,utr:cleanUTR,amount:amt,coins,status:'pending',createdAt:Date.now(),ip,suspicious:!!(u.suspicious&&u.suspicious>2)};
  d.coinRequests.push(req_obj); save(d);
  secLog('COIN_REQUEST',{ip,code:clean,utr:cleanUTR,amount:amt,coins});
  return res.json({ok:true,msg:'Request bhej di! Admin verify karega jald.'});
});

app.post('/withdraw',(req,res)=>{
  const ip=getIP(req);
  if(rateLimit(ip,'withdraw',3,300000)) return res.json({ok:false,msg:'Bahut zyada requests. 5 min baad try karo.'});
  const {code,coins,upiId}=req.body;
  if(!code||!coins||!upiId) return res.json({ok:false,msg:'Saari details daalo'});
  const d=load(); fix(d);
  const clean=code.trim().toUpperCase();
  const u=d.users.find(u=>u.code===clean);
  if(!u||u.banned) return res.json({ok:false,msg:'Invalid code'});
  const c=parseInt(coins);
  const minW=d.settings.minWithdraw||300;
  if(isNaN(c)||c<minW) return res.json({ok:false,msg:`Minimum ${minW} coins withdraw kar sakte ho`});
  if((u.coins||0)<c) return res.json({ok:false,msg:`Aapke paas sirf ${u.coins||0} coins hain`});
  const cleanUpi=String(upiId).trim().substring(0,100);
  if(!cleanUpi||cleanUpi.length<5) return res.json({ok:false,msg:'Valid UPI ID daalo (min 5 characters)'});
  if(d.withdrawRequests.find(r=>r.userCode===clean&&r.status==='pending')) return res.json({ok:false,msg:'Ek withdraw pehle se pending hai. Uska wait karo.'});
  if(withdrawnToday(d,clean)+c>(d.settings.maxWithdrawPerDay||5000)) return res.json({ok:false,msg:`Aaj ki withdraw limit exceed ho gayi`});
  // Fraud check: can't withdraw more than (bought+won)
  const audit=userAudit(d,clean);
  const maxLegal=audit.totalBought+audit.totalWon;
  if(c+audit.totalWithdrawn>maxLegal+50){
    secLog('SUSPICIOUS_WITHDRAW',{ip,code:clean,requesting:c,maxAllowed:maxLegal-audit.totalWithdrawn,audit});
    return res.json({ok:false,msg:'Withdraw nahi ho sakta. Admin se contact karo.'});
  }
  u.coins=(u.coins||0)-c;
  const wr={id:uid(),userCode:clean,userName:u.name,coins:c,upiId:cleanUpi,status:'pending',createdAt:Date.now(),ip,audit};
  d.withdrawRequests.push(wr); save(d);
  secLog('WITHDRAW_REQUEST',{ip,code:clean,coins:c,upiId:cleanUpi});
  return res.json({ok:true,msg:`${c} coins withdraw request bhej di!`,coins:u.coins});
});

// ══ ADMIN ════════════════════════════════════════════════

app.get('/admin/data',(req,res)=>{
  if(!auth(req)){secLog('ADMIN_AUTH_FAIL',{ip:getIP(req)});return res.status(401).json({ok:false});}
  const d=load(); fix(d);
  const r=getRound(d);
  let ns=null;
  if(r&&r.bets){
    ns={};for(let i=0;i<=9;i++)ns[i]={count:0,total:0,bets:[]};
    r.bets.filter(b=>b.status==='approved').forEach(b=>{ns[b.number].count++;ns[b.number].total+=b.amount;ns[b.number].bets.push({name:b.userName,code:b.userCode,amount:b.amount});});
  }
  const ri=r?{...r,betEndsAt:r.startedAt+40*60*1000,roundEndsAt:r.startedAt+60*60*1000}:null;
  return res.json({ok:true,users:d.users,round:ri,numStats:ns,settings:d.settings,
    pendingCoins:d.coinRequests.filter(r=>r.status==='pending').length,
    pendingWithdraw:d.withdrawRequests.filter(r=>r.status==='pending').length,
    suspiciousCount:d.users.filter(u=>(u.suspicious||0)>0||u.banned).length,
    stats:{totalUsers:d.users.length,totalRounds:d.rounds.filter(r=>r.status==='result').length,
      currentBets:r?(r.bets||[]).filter(b=>b.status==='approved').length:0,
      currentAmount:r?(r.bets||[]).filter(b=>b.status==='approved').reduce((s,b)=>s+b.amount,0):0}
  });
});

app.post('/admin/round/start',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const d=load();
  if(getRound(d)) return res.json({ok:false,msg:'Pehle current round finish karo'});
  const r={id:uid(),status:'open',startedAt:Date.now(),closedAt:null,resultAt:null,winNum:null,bets:[]};
  d.rounds.push(r);d.currentRoundId=r.id;save(d);
  secLog('ROUND_START',{id:r.id});
  res.json({ok:true,round:r});
});

app.post('/admin/round/close',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const d=load(),r=getRound(d);
  if(!r||r.status!=='open') return res.json({ok:false,msg:'Koi open round nahi'});
  r.status='closed';r.closedAt=Date.now();save(d);res.json({ok:true});
});

app.post('/admin/round/result',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const num=parseInt(req.body.winNum);
  if(isNaN(num)||num<0||num>9) return res.json({ok:false,msg:'0-9 mein se number daalo'});
  const d=load();fix(d);const r=getRound(d);
  if(!r||r.status==='result') return res.json({ok:false,msg:'Round ready nahi'});
  const mult=d.settings.multiplier||9;
  r.status='result';r.winNum=num;r.resultAt=Date.now();
  const winners=[];
  (r.bets||[]).forEach(b=>{
    if(b.status==='approved'){
      b.won=b.number===num;b.winAmount=b.won?b.amount*mult:0;
      if(b.won){const u=d.users.find(u=>u.code===b.userCode);if(u){u.coins=(u.coins||0)+b.winAmount;winners.push({name:b.userName,code:b.userCode,coins:b.winAmount});}}
    }
  });
  d.currentRoundId=null;save(d);
  secLog('ROUND_RESULT',{winNum:num,winners:winners.length});
  res.json({ok:true,winNum:num,winners});
});

app.get('/admin/coins',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const d=load();fix(d);
  res.json({ok:true,requests:d.coinRequests.slice().reverse()});
});

app.post('/admin/coins/approve',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const {reqId}=req.body;const d=load();fix(d);
  const cr=d.coinRequests.find(r=>r.id===reqId);
  if(!cr) return res.json({ok:false,msg:'Request nahi mili'});
  if(cr.status!=='pending') return res.json({ok:false,msg:'Already processed'});
  // Double-check no other request with same UTR approved
  if(d.coinRequests.find(r=>r.id!==reqId&&r.utr===cr.utr&&r.status==='approved')){
    secLog('DOUBLE_UTR_APPROVE',{utr:cr.utr,reqId});
    return res.json({ok:false,msg:'Yeh UTR already approve ho chuka hai! Check karo.'});
  }
  const u=d.users.find(u=>u.code===cr.userCode);
  if(!u) return res.json({ok:false,msg:'User nahi mila'});
  u.coins=(u.coins||0)+cr.coins;
  cr.status='approved';cr.processedAt=Date.now();
  if(!(d.blockedUTRs||[]).includes(cr.utr)) d.blockedUTRs=[...(d.blockedUTRs||[]),cr.utr];
  save(d);
  secLog('COIN_APPROVED',{code:cr.userCode,utr:cr.utr,coins:cr.coins});
  res.json({ok:true,coins:u.coins});
});

app.post('/admin/coins/reject',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const {reqId,blockUTR}=req.body;const d=load();fix(d);
  const cr=d.coinRequests.find(r=>r.id===reqId);
  if(!cr) return res.json({ok:false,msg:'Request nahi mili'});
  if(cr.status!=='pending') return res.json({ok:false,msg:'Already processed'});
  cr.status='rejected';cr.processedAt=Date.now();
  if(blockUTR&&!(d.blockedUTRs||[]).includes(cr.utr)){
    d.blockedUTRs=[...(d.blockedUTRs||[]),cr.utr];
    secLog('UTR_BLOCKED',{utr:cr.utr,code:cr.userCode});
  }
  save(d);res.json({ok:true});
});

app.get('/admin/withdraw',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const d=load();fix(d);
  res.json({ok:true,requests:d.withdrawRequests.slice().reverse()});
});

app.post('/admin/withdraw/done',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const {reqId}=req.body;const d=load();fix(d);
  const wr=d.withdrawRequests.find(r=>r.id===reqId);
  if(!wr) return res.json({ok:false,msg:'Request nahi mili'});
  if(wr.status!=='pending') return res.json({ok:false,msg:'Already processed'});
  wr.status='paid';wr.paidAt=Date.now();save(d);
  secLog('WITHDRAW_PAID',{code:wr.userCode,coins:wr.coins});
  res.json({ok:true});
});

app.post('/admin/withdraw/reject',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const {reqId}=req.body;const d=load();fix(d);
  const wr=d.withdrawRequests.find(r=>r.id===reqId);
  if(!wr) return res.json({ok:false,msg:'Request nahi mili'});
  if(wr.status!=='pending') return res.json({ok:false,msg:'Already processed'});
  const u=d.users.find(u=>u.code===wr.userCode);
  if(u) u.coins=(u.coins||0)+wr.coins;
  wr.status='rejected';wr.processedAt=Date.now();save(d);
  secLog('WITHDRAW_REJECTED',{code:wr.userCode,coins:wr.coins});
  res.json({ok:true});
});

app.post('/admin/user',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const {name}=req.body;const d=load();const code=genCode();
  d.users.push({code,name:name||'User',createdAt:Date.now(),deviceId:null,coins:0,suspicious:0});
  save(d);res.json({ok:true,code,name:name||'User'});
});

app.delete('/admin/user/:code',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const d=load();d.users=d.users.filter(u=>u.code!==req.params.code);save(d);res.json({ok:true});
});

app.post('/admin/user/resetdevice',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const {code}=req.body;const d=load();
  const u=d.users.find(u=>u.code===code);if(!u) return res.json({ok:false});
  u.deviceId=null;save(d);res.json({ok:true});
});

app.post('/admin/user/ban',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const {code,ban}=req.body;const d=load();
  const u=d.users.find(u=>u.code===code);if(!u) return res.json({ok:false});
  u.banned=!!ban;save(d);
  secLog(ban?'USER_BANNED':'USER_UNBANNED',{code});
  res.json({ok:true});
});

app.post('/admin/user/coins',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const {code,coins}=req.body;const d=load();
  const u=d.users.find(u=>u.code===code);if(!u) return res.json({ok:false});
  const old=u.coins||0;u.coins=Math.max(0,parseInt(coins)||0);save(d);
  secLog('ADMIN_COIN_ADJUST',{code,from:old,to:u.coins});
  res.json({ok:true,coins:u.coins});
});

app.get('/admin/user/audit/:code',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const d=load();fix(d);
  const u=d.users.find(u=>u.code===req.params.code);if(!u) return res.json({ok:false});
  const audit=userAudit(d,req.params.code);
  const bets=d.rounds.flatMap(r=>(r.bets||[]).filter(b=>b.userCode===req.params.code).map(b=>({...b,roundWinNum:r.winNum,resultAt:r.resultAt}))).slice(-20).reverse();
  const coinBuys=d.coinRequests.filter(r=>r.userCode===req.params.code).slice(-20).reverse();
  const withdrawals=d.withdrawRequests.filter(r=>r.userCode===req.params.code).slice(-20).reverse();
  return res.json({ok:true,user:u,audit,bets,coinBuys,withdrawals});
});

app.post('/admin/blockip',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const {ip,block}=req.body;const d=load();fix(d);
  if(block){if(!(d.blockedIPs||[]).includes(ip))d.blockedIPs.push(ip);}
  else{d.blockedIPs=(d.blockedIPs||[]).filter(x=>x!==ip);}
  save(d);secLog(block?'IP_BLOCKED':'IP_UNBLOCKED',{ip});
  res.json({ok:true});
});

app.get('/admin/seclog',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  try{
    const raw=fs.existsSync(LOG)?fs.readFileSync(LOG,'utf8'):'';
    const logs=raw.trim().split('\n').filter(Boolean).slice(-300).reverse().map(l=>{try{return JSON.parse(l);}catch(e){return null;}}).filter(Boolean);
    res.json({ok:true,logs});
  }catch(e){res.json({ok:true,logs:[]});}
});

app.post('/admin/settings',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const {upiId,upiName,minBet,maxBet,multiplier,tgLink,minWithdraw,coinRate,maxCoinBuyPerDay,maxWithdrawPerDay}=req.body;
  const d=load();fix(d);
  if(upiId!==undefined)d.settings.upiId=upiId;
  if(upiName!==undefined)d.settings.upiName=upiName;
  if(minBet!==undefined&&minBet!=='')d.settings.minBet=parseInt(minBet);
  if(maxBet!==undefined&&maxBet!=='')d.settings.maxBet=parseInt(maxBet);
  if(multiplier!==undefined&&multiplier!=='')d.settings.multiplier=parseInt(multiplier);
  if(tgLink!==undefined)d.settings.tgLink=tgLink;
  if(minWithdraw!==undefined&&minWithdraw!=='')d.settings.minWithdraw=parseInt(minWithdraw);
  if(coinRate!==undefined&&coinRate!=='')d.settings.coinRate=parseFloat(coinRate);
  if(maxCoinBuyPerDay!==undefined&&maxCoinBuyPerDay!=='')d.settings.maxCoinBuyPerDay=parseInt(maxCoinBuyPerDay);
  if(maxWithdrawPerDay!==undefined&&maxWithdrawPerDay!=='')d.settings.maxWithdrawPerDay=parseInt(maxWithdrawPerDay);
  save(d);res.json({ok:true,settings:d.settings});
});

app.get('/admin/history',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const d=load();
  res.json({ok:true,history:d.rounds.filter(r=>r.status==='result').reverse()});
});

app.delete('/admin/history/:id',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const d=load();const before=d.rounds.length;
  d.rounds=d.rounds.filter(r=>r.id!==req.params.id);
  if(d.rounds.length===before) return res.json({ok:false,msg:'Round nahi mila'});
  save(d);res.json({ok:true});
});

app.delete('/admin/history',(req,res)=>{
  if(!auth(req)) return res.status(401).json({ok:false});
  const d=load();d.rounds=d.rounds.filter(r=>r.status!=='result');save(d);res.json({ok:true});
});

app.listen(PORT,'0.0.0.0',()=>console.log('Secure server on '+PORT));
