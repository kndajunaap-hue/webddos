import { cors, ratelimit, originGuard, sanitize } from './_guard.js';

export default async function handler(req, res){
  if(!cors(req,res,'POST,OPTIONS')) return;
  if(!originGuard(req,res)) return;
  if(!ratelimit(req,res)) return;
  if(req.method!=='POST') return res.status(405).json({ error:'POST only' });

  const prompt = sanitize(req.body?.prompt || '');
  if(!prompt) return res.status(400).json({ error:'empty prompt' });

  const key = process.env.OPENROUTER_KEY;

  if(!key){
    return res.status(500).json({
      stage:'env',
      error:'OPENROUTER_KEY kosong',
      hint:'set di Vercel → Settings → Environment Variables → Production, lalu REDEPLOY'
    });
  }

  const body = {
    model: 'openrouter/free',  // <-- OTOMATIS PILIH MODEL GRATIS
    messages: [
      { role:'system', content:'Kamu ORACLE, AI commander di ddos-console. Jawab teknis singkat.' },
      { role:'user',   content: prompt }
    ],
    temperature: 0.7,
    max_tokens: 1024
  };

  try {
    const r = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method:'POST',
      headers:{
        'Content-Type':'application/json',
        'Authorization':'Bearer ' + key,
        'HTTP-Referer':'https://ddos-console.vercel.app',
        'X-Title':'ddos-console'
      },
      body: JSON.stringify(body)
    });

    const text = await r.text();

    if(!r.ok){
      return res.status(r.status).json({
        stage:'openrouter_api',
        httpStatus: r.status,
        detail: text.slice(0, 800)
      });
    }

    const data = JSON.parse(text);
    const answer = data.choices?.[0]?.message?.content || '(kosong)';
    return res.json({ answer, model: data.model || body.model });

  } catch(e){
    return res.status(500).json({ stage:'network', error: e.message });
  }
}
