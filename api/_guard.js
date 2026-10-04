import crypto from 'crypto';

const BUCKETS = new Map(); // ip -> {count, ts}
const WINDOW = 60_000;     // 60s
const LIMIT  = 120;        // 120 req/menit

export function ratelimit(req, res){
  const ip = (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
  const now = Date.now();
  const b = BUCKETS.get(ip) || { count:0, ts:now };
  if(now - b.ts > WINDOW){ b.count = 0; b.ts = now; }
  b.count++;
  BUCKETS.set(ip, b);
  if(b.count > LIMIT){
    res.status(429).json({ error:'rate limit exceeded' });
    return false;
  }
  return true;
}

export function originGuard(req, res){
  const origin = req.headers.origin || req.headers.referer || '';
  const host   = req.headers.host || '';
  if(!origin) return true;
  try {
    const o = new URL(origin);
    if(o.host === host) return true;
  } catch(e){}
  res.status(403).json({ error:'forbidden origin' });
  return false;
}

export function tokenGuard(req, res){
  const secret = process.env.CONSOLE_SECRET || 'lynqo-default-secret';
  const token  = req.headers['x-console-token'];
  if(!token){ res.status(401).json({ error:'missing token' }); return false; }
  const expected = crypto.createHmac('sha256', secret).update('console-v2').digest('hex');
  if(token !== expected){ res.status(401).json({ error:'invalid token' }); return false; }
  return true;
}

export function sanitize(str){
  if(typeof str !== 'string') return '';
  return str.replace(/[<>&"'`;]/g,'').slice(0,512);
}

export function validateTarget(t){
  if(!t || typeof t !== 'string') return null;
  t = t.trim();
  if(!/^https?:\/\/[a-z0-9.\-]+(:\d+)?(\/.*)?$/i.test(t)) return null;
  return t;
}

export function cors(req, res, methods='GET,POST,DELETE,OPTIONS'){
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Methods', methods);
  res.setHeader('Access-Control-Allow-Headers','Content-Type,x-console-token');
  res.setHeader('Access-Control-Allow-Credentials','true');
  res.setHeader('Vary','Origin');
  if(req.method==='OPTIONS'){ res.status(200).end(); return false; }
  return true;
}
