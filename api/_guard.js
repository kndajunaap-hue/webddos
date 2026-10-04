const BUCKETS = new Map();
const WINDOW = 60_000;
const LIMIT  = 150;

export function ratelimit(req, res){
  const ip = (req.headers['x-forwarded-for']||'').split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || 'unknown';
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
  const url    = req.url || '';

  // GitHub OAuth callback datang sebagai navigasi langsung
  // gak ada header Origin/Referer -> loloskan
  if(!origin) return true;

  // Khusus callback OAuth, loloskan tanpa cek
  if(url.includes('action=github')) return true;

  try {
    const o = new URL(origin);

    // host sama = lolos
    if(o.host === host) return true;

    // localhost = lolos (buat dev)
    if(o.hostname === 'localhost' || o.hostname === '127.0.0.1') return true;

    // kedua .vercel.app = lolos (preview + production)
    if(o.host.endsWith('.vercel.app') && host.endsWith('.vercel.app')) return true;

  } catch(e){
    return true;
  }

  res.status(403).json({ error:'forbidden origin', your_origin: origin, expected_host: host });
  return false;
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

export function cors(req, res, methods){
  methods = methods || 'GET,POST,DELETE,OPTIONS';
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Methods', methods);
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
  res.setHeader('Access-Control-Allow-Credentials','true');
  res.setHeader('Vary','Origin');
  if(req.method === 'OPTIONS'){ res.status(200).end(); return false; }
  return true;
}
