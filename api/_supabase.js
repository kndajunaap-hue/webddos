const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || '';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

export function supabaseReady(){
  return !!(SUPABASE_URL && SUPABASE_ANON_KEY && SUPABASE_SERVICE_ROLE_KEY);
}

export async function requireUser(req){
  if(!SUPABASE_URL || !SUPABASE_ANON_KEY) return { error:'Supabase Auth belum dikonfigurasi.', status:503 };
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i,'');
  if(!token) return { error:'Sesi login diperlukan.', status:401 };
  try {
    const response = await fetch(SUPABASE_URL + '/auth/v1/user', {
      headers:{ 'apikey':SUPABASE_ANON_KEY, 'Authorization':'Bearer ' + token }
    });
    const user = await response.json();
    if(!response.ok || !user.id) return { error:'Sesi tidak valid atau sudah berakhir.', status:401 };
    return { user:user };
  } catch(e){ return { error:'Tidak dapat memvalidasi sesi Supabase.', status:502 }; }
}

export async function dbRequest(path, options){
  if(!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) throw new Error('Supabase service role belum dikonfigurasi.');
  options = options || {};
  const headers = Object.assign({
    'apikey':SUPABASE_SERVICE_ROLE_KEY,
    'Authorization':'Bearer ' + SUPABASE_SERVICE_ROLE_KEY,
    'Content-Type':'application/json'
  }, options.headers || {});
  const response = await fetch(SUPABASE_URL + '/rest/v1/' + path, Object.assign({}, options, { headers:headers }));
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch(e){ body = { message:text.slice(0,500) }; }
  if(!response.ok){
    const error = new Error(body && (body.message || body.hint) || 'Supabase database request failed.');
    error.status = response.status;
    throw error;
  }
  return body;
}

export function usernameFor(user){
  const meta = user && user.user_metadata || {};
  return String(meta.username || user && user.email && user.email.split('@')[0] || 'member').slice(0,48);
}
