import { cors, ratelimit, originGuard, sanitize } from './_guard.js';

export default async function handler(req, res){
  if(!cors(req,res,'POST,OPTIONS')) return;
  if(!originGuard(req,res)) return;
  if(!ratelimit(req,res)) return;
  if(req.method!=='POST') return res.status(405).json({ error:'POST only' });

  const prompt = sanitize(req.body?.prompt || '');
  if(!prompt) return res.status(400).json({ error:'empty prompt' });

  const key = process.env.GROQ_KEY_1;

  // ==== CEK KEY ADA ATAU NGGAK ====
  if(!key){
    return res.status(500).json({
      stage:'env',
      error:'GROQ_KEY_1 kosong',
      hint:'set di Vercel → Settings → Environment Variables → Production, lalu REDEPLOY',
      allEnv: {
        GROQ_KEY_1: !!process.env.GROQ_KEY_1,
        GROQ_KEY_2: !!process.env.GROQ_KEY_2,
        GROQ_KEY_3: !!process.env.GROQ_KEY_3
      }
    });
  }

  // ==== CEK KEY FORMAT ====
  if(!key.startsWith('gsk_')){
    return res.status(500).json({
      stage:'key_format',
      error:'GROQ_KEY_1 format salah',
      detail:'key harus mulai dengan gsk_, panjang key kamu: ' + key.length,
      prefix: key.slice(0,8)
    });
  }

  const body = {
    model: 'openai/gpt-oss-120b',
    messages: [
      { role:'system', content:'Kamu ORACLE, AI commander di ddos-console. Jawab teknis singkat.' },
      { role:'user',   content: prompt }
    ],
    temperature: 0.7,
    max_tokens: 1024
  };

  try {
    const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method:'POST',
      headers:{
        'Content-Type':'application/json',
        'Authorization':'Bearer ' + key
      },
      body: JSON.stringify(body)
    });

    const text = await r.text();

    if(!r.ok){
      return res.status(r.status).json({
        stage:'groq_api',
        error:'groq rejected request',
        httpStatus: r.status,
        detail: text.slice(0, 800)
      });
    }

    let data;
    try { data = JSON.parse(text); }
    catch(e){ return res.status(500).json({ stage:'parse', error:'groq response not json', raw:text.slice(0,300) }); }

    const answer = data.choices?.[0]?.message?.content || '(kosong)';
    return res.json({ answer, model: body.model });

  } catch(e){
    return res.status(500).json({
      stage:'network',
      error:'gagal konek ke groq',
      detail: e.message
    });
  }
}
