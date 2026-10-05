import { cors, ratelimit, originGuard } from './_guard.js';

function config(){
  return {
    url:(process.env.SUPABASE_URL || '').replace(/\/$/, ''),
    anonKey:process.env.SUPABASE_ANON_KEY || ''
  };
}

export default async function handler(req, res){
  if(!cors(req,res,'POST,GET,OPTIONS')) return;
  if(!originGuard(req,res)) return;
  if(!ratelimit(req,res)) return;
  const action = (req.query && req.query.action) || (req.body && req.body.action);
  const c = config();

  if(action === 'config' && req.method === 'GET'){
    const redirectTo = (req.headers.origin || '') + '/';
    return res.json({
      configured:!!(c.url && c.anonKey),
      githubUrl:c.url ? c.url + '/auth/v1/authorize?provider=github&redirect_to=' + encodeURIComponent(redirectTo) : ''
    });
  }

  if(!c.url || !c.anonKey) return res.status(503).json({ error:'Supabase belum dikonfigurasi. Isi SUPABASE_URL dan SUPABASE_ANON_KEY.' });

  if(action === 'register' && req.method === 'POST'){
    const email = String(req.body && (req.body.email || req.body.username) || '').trim().toLowerCase();
    const password = String(req.body && req.body.password || '');
    const username = String(req.body && req.body.username || email.split('@')[0]).trim().slice(0,48);
    if(!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error:'Masukkan alamat email yang valid.' });
    if(password.length < 8) return res.status(400).json({ error:'Password minimal 8 karakter.' });
    try {
      const r = await fetch(c.url + '/auth/v1/signup', {
        method:'POST',
        headers:{'Content-Type':'application/json','apikey':c.anonKey},
        body:JSON.stringify({ email:email, password:password, data:{ username:username } })
      });
      const d = await r.json();
      if(!r.ok) return res.status(r.status).json({ error:d.msg || d.message || d.error_description || d.error || 'Pendaftaran gagal.' });
      if(d.access_token) return res.json({ ok:true, username:username, access_token:d.access_token, refresh_token:d.refresh_token });
      return res.json({ ok:true, username:username, confirmationRequired:true });
    } catch(e){ return res.status(502).json({ error:'Supabase tidak dapat dijangkau.' }); }
  }

  if(action === 'login' && req.method === 'POST'){
    const email = String(req.body && (req.body.email || req.body.username) || '').trim().toLowerCase();
    const password = String(req.body && req.body.password || '');
    if(!email || !password) return res.status(400).json({ error:'Email dan password wajib diisi.' });
    try {
      const r = await fetch(c.url + '/auth/v1/token?grant_type=password', {
        method:'POST',
        headers:{'Content-Type':'application/json','apikey':c.anonKey},
        body:JSON.stringify({ email:email, password:password })
      });
      const d = await r.json();
      if(!r.ok || !d.access_token) return res.status(401).json({ error:d.msg || d.message || d.error_description || 'Email atau password salah.' });
      const username = d.user && d.user.user_metadata && d.user.user_metadata.username || (d.user && d.user.email || email).split('@')[0];
      return res.json({ ok:true, username:username, access_token:d.access_token, refresh_token:d.refresh_token });
    } catch(e){ return res.status(502).json({ error:'Supabase tidak dapat dijangkau.' }); }
  }

  if(action === 'me' && req.method === 'GET'){
    const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i,'');
    if(!token) return res.status(401).json({ error:'Sesi tidak ada.' });
    try {
      const r = await fetch(c.url + '/auth/v1/user', { headers:{'apikey':c.anonKey,'Authorization':'Bearer ' + token} });
      const d = await r.json();
      if(!r.ok) return res.status(401).json({ error:'Sesi berakhir. Silakan masuk kembali.' });
      return res.json({ id:d.id, email:d.email, username:d.user_metadata && d.user_metadata.username || (d.email || '').split('@')[0] });
    } catch(e){ return res.status(502).json({ error:'Tidak dapat memvalidasi sesi.' }); }
  }

  if(action === 'refresh' && req.method === 'POST'){
    const refreshToken = String(req.body && req.body.refresh_token || '');
    if(!refreshToken) return res.status(401).json({ error:'Sesi berakhir. Silakan masuk kembali.' });
    try {
      const r = await fetch(c.url + '/auth/v1/token?grant_type=refresh_token', {
        method:'POST', headers:{'Content-Type':'application/json','apikey':c.anonKey},
        body:JSON.stringify({ refresh_token:refreshToken })
      });
      const d = await r.json();
      if(!r.ok || !d.access_token) return res.status(401).json({ error:'Sesi berakhir. Silakan masuk kembali.' });
      const username = d.user && d.user.user_metadata && d.user.user_metadata.username || (d.user && d.user.email || '').split('@')[0];
      return res.json({ access_token:d.access_token, refresh_token:d.refresh_token, username:username });
    } catch(e){ return res.status(502).json({ error:'Tidak dapat memperbarui sesi.' }); }
  }

  return res.status(400).json({ error:'unknown action' });
}
