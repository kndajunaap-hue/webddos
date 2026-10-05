import crypto from 'crypto';
import { cors, ratelimit, sanitize } from './_guard.js';
import { dbRequest, requireUser, usernameFor } from './_supabase.js';

function hashKey(key){
  return crypto.createHash('sha256').update(key).digest('hex');
}

export function createKey(opts){
  opts = opts || {};
  const secret = process.env.APIKEY_SECRET;
  if(!secret) throw new Error('APIKEY_SECRET is required for legacy keys.');
  const tier = opts.tier || 'free';
  const days = opts.days || 6;
  const owner = opts.owner || 'admin';
  const now = Date.now();
  const expiresAt = now + days * 24 * 60 * 60 * 1000;
  const payload = JSON.stringify({ t:tier, o:owner, e:expiresAt, i:now, r:crypto.randomBytes(5).toString('hex') });
  const b64 = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(b64).digest('hex').slice(0,24);
  const prefix = tier === 'elite' ? 'lk_elite' : tier === 'pro' ? 'lk_pro' : 'lk_free';
  return { key:prefix + '_' + b64 + '.' + sig, tier:tier, owner:owner, createdAt:now, expiresAt:expiresAt, active:true };
}

export async function validateKey(key){
  if(!key || typeof key !== 'string') return null;
  if(key.startsWith('sk_leo_')){
    try {
      const rows = await dbRequest('api_keys?select=id,user_id,expires_at,revoked_at&key_hash=eq.' + hashKey(key) + '&limit=1');
      const row = rows && rows[0];
      if(!row || row.revoked_at || (row.expires_at && Date.parse(row.expires_at) <= Date.now())) return null;
      dbRequest('api_keys?id=eq.' + encodeURIComponent(row.id), {
        method:'PATCH',
        headers:{'Prefer':'return=minimal'},
        body:JSON.stringify({ last_used_at:new Date().toISOString() })
      }).catch(function(){});
      return { tier:'free', owner:row.user_id, userId:row.user_id, keyId:row.id, active:true };
    } catch(e){ return null; }
  }
  const secret = process.env.APIKEY_SECRET;
  if(!secret) return null;
  try {
    const parts = key.split('_');
    if(parts.length < 3) return null;
    const rest = parts.slice(2).join('_');
    const dotIdx = rest.lastIndexOf('.');
    if(dotIdx === -1) return null;
    const b64 = rest.slice(0,dotIdx), sig = rest.slice(dotIdx + 1);
    const expected = crypto.createHmac('sha256',secret).update(b64).digest('hex').slice(0,24);
    const a = Buffer.from(sig), b = Buffer.from(expected);
    if(a.length !== b.length || !crypto.timingSafeEqual(a,b)) return null;
    const payload = JSON.parse(Buffer.from(b64,'base64url').toString());
    if(Date.now() > payload.e) return null;
    return { tier:payload.t, owner:payload.o, createdAt:payload.i, expiresAt:payload.e, active:true };
  } catch(e){ return null; }
}

export default async function handler(req,res){
  if(!cors(req,res,'GET,POST,OPTIONS')) return;
  if(!ratelimit(req,res)) return;
  const auth = await requireUser(req);
  if(auth.error) return res.status(auth.status).json({ error:auth.error });
  const user = auth.user;
  try {
    if(req.method === 'GET'){
      const rows = await dbRequest('api_keys?select=id,key_prefix,label,created_at,expires_at,revoked_at,last_used_at&user_id=eq.' + encodeURIComponent(user.id) + '&order=created_at.desc');
      return res.json({ keys:rows || [] });
    }
    const action = req.body && req.body.action;
    if(action === 'create'){
      const existing = await dbRequest('api_keys?select=id&user_id=eq.' + encodeURIComponent(user.id) + '&revoked_at=is.null');
      if(existing && existing.length >= 5) return res.status(409).json({ error:'Maksimal 5 API key aktif per akun.' });
      const label = sanitize(req.body && req.body.label || 'My application').trim().slice(0,80) || 'My application';
      const raw = 'sk_leo_' + crypto.randomBytes(32).toString('base64url');
      const inserted = await dbRequest('api_keys', {
        method:'POST',
        headers:{'Prefer':'return=representation'},
        body:JSON.stringify({ user_id:user.id, key_hash:hashKey(raw), key_prefix:raw.slice(0,14), label:label })
      });
      return res.status(201).json({ key:raw, record:inserted && inserted[0] });
    }
    if(action === 'revoke'){
      const id = String(req.body && req.body.id || '').replace(/[^a-f0-9-]/gi,'');
      if(!id) return res.status(400).json({ error:'ID key tidak valid.' });
      await dbRequest('api_keys?id=eq.' + encodeURIComponent(id) + '&user_id=eq.' + encodeURIComponent(user.id) + '&revoked_at=is.null', {
        method:'PATCH',
        headers:{'Prefer':'return=minimal'},
        body:JSON.stringify({ revoked_at:new Date().toISOString() })
      });
      return res.json({ ok:true });
    }
    return res.status(400).json({ error:'Aksi API key tidak dikenal.' });
  } catch(e){
    return res.status(e.status || 503).json({ error:e.message || 'Supabase API key store unavailable.' });
  }
}
