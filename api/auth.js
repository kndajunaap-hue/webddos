import { cors, ratelimit, originGuard, sanitize } from './_guard.js';

// ==== User storage (in-memory, cold start akan reset) ====
// Untuk production persistent, ganti ke Vercel KV / Supabase
const USERS = new Map();

export default async function handler(req, res){
  if(!cors(req,res,'POST,GET,OPTIONS')) return;
  if(!originGuard(req,res)) return;
  if(!ratelimit(req,res)) return;

  const action = (req.query && req.query.action) || (req.body && req.body.action);

  // ============ GitHub OAuth Callback ============
  if(action === 'github' && req.method === 'GET'){
    const code = req.query && req.query.code;
    if(!code){
      return res.redirect(302, '/?leo_err=no_code');
    }

    try {
      const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          client_id: process.env.GITHUB_CLIENT_ID,
          client_secret: process.env.GITHUB_CLIENT_SECRET,
          code: code
        })
      });

      const tokenData = await tokenRes.json();

      if(tokenData.error){
        return res.redirect(302, '/?leo_err=' + encodeURIComponent(tokenData.error));
      }

      const userRes = await fetch('https://api.github.com/user', {
        headers: {
          'Authorization': 'Bearer ' + tokenData.access_token,
          'User-Agent': 'ddos-console'
        }
      });

      const user = await userRes.json();

      USERS.set('gh_' + user.id, {
        password: null,
        githubId: user.id,
        avatar: user.avatar_url,
        name: user.login
      });

      const sessionToken = 'leo_' + Date.now() + '_' + Math.random().toString(36).slice(2,10);

      return res.redirect(302, '/?leo_token=' + sessionToken + '&leo_user=' + encodeURIComponent(user.login) + '&leo_avatar=' + encodeURIComponent(user.avatar_url || ''));
    } catch(e){
      return res.redirect(302, '/?leo_err=' + encodeURIComponent(e.message));
    }
  }

  // ============ Register ============
  if(action === 'register' && req.method === 'POST'){
    const username = sanitize(req.body && req.body.username || '');
    const password = sanitize(req.body && req.body.password || '');

    if(!username || !password){
      return res.status(400).json({ error: 'username dan password wajib diisi' });
    }
    if(username.length < 3){
      return res.status(400).json({ error: 'username minimal 3 karakter' });
    }
    if(password.length < 4){
      return res.status(400).json({ error: 'password minimal 4 karakter' });
    }
    if(USERS.has(username)){
      return res.status(409).json({ error: 'username sudah dipakai' });
    }

    USERS.set(username, {
      password: password,
      githubId: null,
      avatar: null,
      name: username
    });

    return res.json({ ok: true, username: username });
  }

  // ============ Login ============
  if(action === 'login' && req.method === 'POST'){
    const username = sanitize(req.body && req.body.username || '');
    const password = sanitize(req.body && req.body.password || '');

    const u = USERS.get(username);
    if(!u || u.password !== password){
      return res.status(401).json({ error: 'username atau password salah' });
    }

    const sessionToken = 'leo_' + Date.now() + '_' + Math.random().toString(36).slice(2,10);
    return res.json({ ok: true, username: username, token: sessionToken });
  }

  // ============ Get GitHub Client ID (untuk frontend) ============
  if(action === 'config' && req.method === 'GET'){
    return res.json({
      githubClientId: process.env.GITHUB_CLIENT_ID || ''
    });
  }

  return res.status(400).json({ error: 'unknown action' });
}
