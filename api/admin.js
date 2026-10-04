import { cors, ratelimit, originGuard, sanitize } from './_guard.js';
import { createKey, listKeys, revokeKey, deleteKey } from './apikey.js';

const ADMINS = global.__LEO_ADMINS || (global.__LEO_ADMINS = new Set());
const OWNER  = (process.env.OWNER_USERNAME || 'LeoXD').toLowerCase();

function isAdmin(username){
  if(!username) return false;
  const u = String(username).toLowerCase();
  return u === OWNER || ADMINS.has(u);
}

export default async function handler(req, res){
  if(!cors(req,res,'POST,GET,OPTIONS')) return;
  if(!originGuard(req,res)) return;
  if(!ratelimit(req,res)) return;

  const body = req.body || {};
  const action = body.action || (req.query && req.query.action);
  const user = sanitize(body.user || (req.query && req.query.user) || '');

  if(action !== 'checkAdmin' && !isAdmin(user)){
    return res.status(403).json({ error: 'akses ditolak: bukan admin' });
  }

  if(action === 'checkAdmin'){
    return res.json({ isAdmin: isAdmin(user), owner: OWNER });
  }

  if(action === 'createKey'){
    const tier = sanitize(body.tier || 'free');
    const days = Math.min(Math.max(+body.days || 14, 1), 3650);

    if(tier !== 'free' && tier !== 'pro' && tier !== 'elite'){
      return res.status(400).json({ error: 'tier tidak valid' });
    }

    const k = createKey({ tier: tier, days: days, owner: user });
    return res.json({ ok: true, key: k });
  }

  if(action === 'listKeys'){
    return res.json({ ok: true, keys: listKeys() });
  }

  if(action === 'revokeKey'){
    const key = sanitize(body.key || '');
    if(!key) return res.status(400).json({ error: 'key kosong' });
    return res.json({ ok: revokeKey(key) });
  }

  if(action === 'deleteKey'){
    const key = sanitize(body.key || '');
    if(!key) return res.status(400).json({ error: 'key kosong' });
    return res.json({ ok: deleteKey(key) });
  }

  if(action === 'addAdmin'){
    const newUser = sanitize(body.newAdmin || '').toLowerCase();
    if(!newUser || newUser.length < 3){
      return res.status(400).json({ error: 'username admin minimal 3 karakter' });
    }
    ADMINS.add(newUser);
    return res.json({ ok: true, admins: [OWNER].concat(Array.from(ADMINS)) });
  }

  if(action === 'removeAdmin'){
    const target = sanitize(body.target || '').toLowerCase();
    if(target === OWNER){
      return res.status(403).json({ error: 'tidak bisa hapus owner' });
    }
    ADMINS.delete(target);
    return res.json({ ok: true, admins: [OWNER].concat(Array.from(ADMINS)) });
  }

  if(action === 'listAdmins'){
    return res.json({ ok: true, owner: OWNER, admins: Array.from(ADMINS) });
  }

  return res.status(400).json({ error: 'unknown action' });
}
