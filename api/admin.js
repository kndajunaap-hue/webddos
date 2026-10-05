import { cors, ratelimit } from './_guard.js';
import { createKey } from './apikey.js';
import { requireUser } from './_supabase.js';

const OWNER_EMAIL = (process.env.OWNER_EMAIL || '').toLowerCase();
const ADMINS = global.__LEO_ADMINS || (global.__LEO_ADMINS = new Set());

function isAdmin(email){
  const address = String(email || '').toLowerCase();
  return !!address && (address === OWNER_EMAIL || ADMINS.has(address));
}

export default async function handler(req,res){
  if(!cors(req,res,'POST,GET,OPTIONS')) return;
  if(!ratelimit(req,res)) return;
  const auth = await requireUser(req);
  if(auth.error) return res.status(auth.status).json({ error:auth.error });
  const email = String(auth.user.email || '').toLowerCase();
  const body = req.body || {};
  const action = body.action || (req.query && req.query.action);

  if(action === 'checkAdmin') return res.json({ isAdmin:isAdmin(email), owner:OWNER_EMAIL });
  if(!isAdmin(email)) return res.status(403).json({ error:'akses ditolak: bukan admin' });

  if(action === 'autoFreeKey'){
    const key = createKey({ tier:'free', days:6, owner:email });
    return res.json({ ok:true, key:key });
  }
  if(action === 'createKey'){
    const tier = String(body.tier || 'free');
    const days = Math.min(Math.max(+body.days || 6,1),3650);
    if(!['free','pro','elite'].includes(tier)) return res.status(400).json({ error:'tier tidak valid' });
    return res.json({ ok:true, key:createKey({ tier:tier, days:days, owner:email }) });
  }
  if(action === 'addAdmin'){
    const newEmail = String(body.newAdmin || '').trim().toLowerCase();
    if(!/^\S+@\S+\.\S+$/.test(newEmail)) return res.status(400).json({ error:'masukkan email admin yang valid' });
    if(newEmail !== OWNER_EMAIL) ADMINS.add(newEmail);
    return res.json({ ok:true, admins:[OWNER_EMAIL].concat(Array.from(ADMINS)) });
  }
  if(action === 'removeAdmin'){
    const target = String(body.target || '').trim().toLowerCase();
    if(target === OWNER_EMAIL) return res.status(403).json({ error:'tidak bisa hapus owner' });
    ADMINS.delete(target);
    return res.json({ ok:true, admins:[OWNER_EMAIL].concat(Array.from(ADMINS)) });
  }
  if(action === 'listAdmins') return res.json({ ok:true, owner:OWNER_EMAIL, admins:Array.from(ADMINS) });
  return res.status(400).json({ error:'unknown action' });
}
