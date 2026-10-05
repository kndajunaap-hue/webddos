import { cors, ratelimit } from './_guard.js';
import { dbRequest, requireUser, usernameFor } from './_supabase.js';

const MAX_SOURCE_BYTES = 50_000;
const SAFE_EXTENSIONS = new Set(['.js','.ts','.jsx','.tsx','.py','.ps1','.sh','.json','.html','.css','.go','.rs','.cpp','.c','.h','.cs','.java','.php','.rb','.sql','.md']);

function clean(value,max){
  return String(value || '').replace(/[\u0000-\u001f\u007f]/g,' ').trim().slice(0,max);
}
function validId(value){
  const id = String(value || '');
  return /^[0-9a-f-]{36}$/i.test(id) ? id : '';
}

export default async function handler(req,res){
  if(!cors(req,res,'GET,POST,DELETE,OPTIONS')) return;
  if(!ratelimit(req,res)) return;
  const auth = await requireUser(req);
  if(auth.error) return res.status(auth.status).json({ error:auth.error });
  const user = auth.user;
  const username = usernameFor(user);

  try {
    if(req.method === 'GET'){
      const action = req.query && req.query.action;
      if(action === 'comments'){
        const scriptId = validId(req.query && req.query.scriptId);
        if(!scriptId) return res.status(400).json({ error:'Script ID tidak valid.' });
        const comments = await dbRequest('script_comments?select=id,script_id,user_id,username,body,created_at&script_id=eq.' + encodeURIComponent(scriptId) + '&order=created_at.asc&limit=100');
        return res.json({ comments:comments || [] });
      }
      const posts = await dbRequest('script_posts?select=id,user_id,username,caption,file_name,language,source_code,downloads,created_at,likes:script_likes(count),comments:script_comments(count)&order=created_at.desc&limit=50');
      if(posts && posts.length){
        const ids = posts.map(function(post){ return post.id; }).join(',');
        const liked = await dbRequest('script_likes?select=script_id&user_id=eq.' + encodeURIComponent(user.id) + '&script_id=in.(' + ids + ')');
        const likedIds = new Set((liked || []).map(function(row){ return row.script_id; }));
        posts.forEach(function(post){ post.liked = likedIds.has(post.id); post.owned = post.user_id === user.id; });
      }
      return res.json({ posts:posts || [] });
    }

    const body = req.body || {};
    const action = body.action;
    if(action === 'upload'){
      const caption = clean(body.caption,500);
      const fileName = clean(body.fileName,120);
      const source = String(body.source || '');
      const dot = fileName.lastIndexOf('.');
      const ext = dot >= 0 ? fileName.slice(dot).toLowerCase() : '';
      if(!caption) return res.status(400).json({ error:'Tambahkan caption untuk script ini.' });
      if(!SAFE_EXTENSIONS.has(ext)) return res.status(400).json({ error:'Tipe file script ini belum didukung.' });
      if(!source || Buffer.byteLength(source,'utf8') > MAX_SOURCE_BYTES) return res.status(400).json({ error:'File kosong atau lebih besar dari 50 KB.' });
      const language = clean(body.language || ext.slice(1),24);
      const rows = await dbRequest('script_posts', {
        method:'POST',
        headers:{'Prefer':'return=representation'},
        body:JSON.stringify({ user_id:user.id, username:username, caption:caption, file_name:fileName, language:language, source_code:source })
      });
      return res.status(201).json({ post:rows && rows[0] });
    }

    const scriptId = validId(body.scriptId);
    if(!scriptId) return res.status(400).json({ error:'Script ID tidak valid.' });

    if(action === 'like'){
      await dbRequest('script_likes?on_conflict=script_id%2Cuser_id', {
        method:'POST',
        headers:{'Prefer':'resolution=merge-duplicates,return=minimal'},
        body:JSON.stringify({ script_id:scriptId, user_id:user.id })
      });
      return res.json({ ok:true });
    }
    if(action === 'unlike'){
      await dbRequest('script_likes?script_id=eq.' + encodeURIComponent(scriptId) + '&user_id=eq.' + encodeURIComponent(user.id), { method:'DELETE' });
      return res.json({ ok:true });
    }
    if(action === 'comment'){
      const comment = clean(body.comment,1200);
      if(!comment) return res.status(400).json({ error:'Komentar tidak boleh kosong.' });
      const rows = await dbRequest('script_comments', {
        method:'POST',
        headers:{'Prefer':'return=representation'},
        body:JSON.stringify({ script_id:scriptId, user_id:user.id, username:username, body:comment })
      });
      return res.status(201).json({ comment:rows && rows[0] });
    }
    if(action === 'download'){
      await dbRequest('rpc/increment_script_download', {
        method:'POST',
        body:JSON.stringify({ p_script_id:scriptId })
      });
      return res.json({ ok:true });
    }
    if(action === 'delete'){
      await dbRequest('script_posts?id=eq.' + encodeURIComponent(scriptId) + '&user_id=eq.' + encodeURIComponent(user.id), { method:'DELETE' });
      return res.json({ ok:true });
    }
    return res.status(400).json({ error:'Aksi Script Hub tidak dikenal.' });
  } catch(e){
    return res.status(e.status || 503).json({ error:e.message || 'Supabase Script Hub tidak tersedia.' });
  }
}
