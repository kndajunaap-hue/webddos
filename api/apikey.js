import { cors, ratelimit, originGuard, sanitize } from './_guard.js';

const KEYS = global.__LEO_KEYS || (global.__LEO_KEYS = new Map());

function genKey(prefix){
  var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  var s = '';
  for(var i=0;i<24;i++) s += chars[Math.floor(Math.random()*chars.length)];
  return prefix + '_' + s;
}

export function validateKey(key){
  if(!key) return null;
  const k = KEYS.get(key);
  if(!k) return null;
  if(!k.active) return null;
  if(Date.now() > k.expiresAt) return null;
  k.usage = (k.usage || 0) + 1;
  return k;
}

export function createKey(opts){
  opts = opts || {};
  const tier   = opts.tier   || 'free';
  const days   = opts.days   || 14;
  const owner  = opts.owner  || 'unknown';
  const prefix = tier === 'elite' ? 'lk_elite' : tier === 'pro' ? 'lk_pro' : 'lk_free';
  const key    = genKey(prefix);
  const now    = Date.now();

  KEYS.set(key, {
    key: key,
    tier: tier,
    owner: owner,
    createdAt: now,
    expiresAt: now + days * 24 * 60 * 60 * 1000,
    active: true,
    usage: 0
  });
  return KEYS.get(key);
}

export function listKeys(){
  var arr = [];
  KEYS.forEach(function(v){ arr.push(v); });
  return arr;
}

export function revokeKey(key){
  var k = KEYS.get(key);
  if(!k) return false;
  k.active = false;
  return true;
}

export function deleteKey(key){
  return KEYS.delete(key);
}

export default async function handler(req, res){
  if(!cors(req,res,'POST,GET,OPTIONS')) return;
  if(!originGuard(req,res)) return;
  if(!ratelimit(req,res)) return;

  if(req.method === 'POST' && req.body && req.body.action === 'validate'){
    const k = validateKey(sanitize(req.body.key || ''));
    if(!k) return res.status(401).json({ valid: false, error: 'invalid or expired key' });
    return res.json({
      valid: true,
      tier: k.tier,
      expiresAt: k.expiresAt,
      usage: k.usage
    });
  }

  return res.status(400).json({ error: 'unknown action' });
}
