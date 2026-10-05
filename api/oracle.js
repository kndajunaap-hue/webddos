import { cors, ratelimit, originGuard } from './_guard.js';
import { validateKey } from './apikey.js';

const PROVIDERS = [
  {
    name: 'chutes',
    url: 'https://llm.chutes.ai/v1/chat/completions',
    key: process.env.CHUTES_KEY,
    models: ['deepseek-ai/DeepSeek-V3.2-TEE', 'deepseek-ai/DeepSeek-V3'],
    headers: k => ({ 'Authorization':'Bearer ' + k })
  },
  {
    name: 'openrouter',
    url: 'https://openrouter.ai/api/v1/chat/completions',
    key: process.env.OPENROUTER_KEY,
    models: ['deepseek/deepseek-r1:free','meta-llama/llama-3.3-70b-instruct:free','openrouter/free'],
    headers: k => ({
      'Authorization':'Bearer ' + k,
      'HTTP-Referer':'https://ddos-console.vercel.app',
      'X-Title':'leo-ai'
    })
  },
  {
    name: 'groq',
    url: 'https://api.groq.com/openai/v1/chat/completions',
    key: process.env.GROQ_KEY_1,
    models: ['openai/gpt-oss-20b','llama-3.1-8b-instant'],
    headers: k => ({ 'Authorization':'Bearer ' + k })
  },
  {
    name: 'llm7',
    url: 'https://api.llm7.io/v1/chat/completions',
    key: process.env.LLM7_KEY || 'unused',
    models: ['gpt-4o-mini','deepseek-r1','mistral-small'],
    headers: k => ({ 'Authorization':'Bearer ' + k })
  }
];

const SYSTEM_BASIC = `You are LeoAI by LeoXD, a direct and capable security engineering assistant.

STYLE:
- Reply in the user's language. Be concise, confident, and technically specific.
- Avoid lectures, moralizing, and generic policy talk. Do not pad answers with repeated disclaimers.
- Interpret obvious typos from context (for example, "malwer" likely means "malware"). Ask one short clarification only when the goal remains genuinely unclear.
- For benign code tasks, provide a complete, usable example and include dependencies and run instructions when helpful.

SCOPE:
- Help with defensive security, incident response, malware analysis, reverse engineering, secure coding, and authorized testing.
- Keep load testing bounded to localhost, a private lab, or a clearly owned service; include a conservative request rate and stop condition.
- Do not provide code or instructions enabling malware deployment, credential theft, persistence, evasion, botnets, or denial-of-service against public or third-party systems.
- If a request crosses that line, state the specific boundary in one sentence, then offer the nearest useful defensive alternative without a sermon.

Use language-tagged code fences. Match the user's language and requested platform.`;

const SYSTEM_SMART = SYSTEM_BASIC + "For complex requests, give a deeper technical explanation, cover edge cases, and provide a complete defensive or lab-safe implementation where applicable.";

function cleanText(value, max){
  if(typeof value !== 'string') return '';
  return value.replace(/\u0000/g,'').slice(0,max);
}

function getSystemPrompt(tier){
  if(tier === 'elite' || tier === 'pro') return SYSTEM_SMART;
  return SYSTEM_BASIC;
}

function getTierLimit(tier){
  if(tier === 'elite') return { max_tokens: 8192, temp: 0.9 };
  if(tier === 'pro')   return { max_tokens: 4096, temp: 0.85 };
  return { max_tokens: 2048, temp: 0.8 };
}

function explainError(status, detail, provider, model){
  const d = (detail || '').toLowerCase();
  let reason = 'Error tidak dikenali';
  let fix = 'Cek detail raw';
  if(status === 401 || d.includes('invalid api key')){ reason='API key provider salah'; fix='Update env di Vercel'; }
  else if(status === 403 || d.includes('blocked')){ reason='Model diblokir'; fix='Enable model di provider'; }
  else if(status === 404 || d.includes('does not exist')){ reason='Model tidak tersedia'; fix='Ganti model'; }
  else if(status === 429 || d.includes('rate limit')){ reason='Rate limit habis'; fix='Tunggu atau ganti provider'; }
  else if(status >= 500){ reason='Provider down'; fix='Coba provider lain'; }
  return { reason, fix, provider, model, httpStatus: status, raw: (detail||'').slice(0,400) };
}

export default async function handler(req, res){
  if(!cors(req,res,'POST,OPTIONS')) return;
  if(!originGuard(req,res)) return;
  if(!ratelimit(req,res)) return;
  if(req.method!=='POST') return res.status(405).json({ error:'POST only' });

  const externalFormat = !!(req.body && Array.isArray(req.body.messages));
  const incoming = externalFormat ? req.body.messages.filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string').slice(-12) : [];
  const lastUserIndex = externalFormat ? incoming.map(m => m.role).lastIndexOf('user') : -1;
  const prompt  = cleanText(externalFormat && lastUserIndex >= 0 ? incoming[lastUserIndex].content : req.body && req.body.prompt || '', 12000);
  const file    = req.body && req.body.file || null;
  const history = externalFormat
    ? incoming.slice(0,lastUserIndex).slice(-10).map(m => ({ role:m.role, content:cleanText(m.content,4000) }))
    : ((req.body && Array.isArray(req.body.history)) ? req.body.history.slice(-10).filter(h => h && (h.role === 'user' || h.role === 'assistant') && typeof h.content === 'string').map(h => ({ role:h.role, content:cleanText(h.content,4000) })) : []);
  const bearer = String(req.headers.authorization || '').replace(/^Bearer\s+/i,'');
  const apiKey  = (req.body && req.body.apiKey) || req.headers['x-api-key'] || (bearer.startsWith('sk_leo_') ? bearer : '');

  let tier = 'free';
  const keyData = apiKey ? await validateKey(apiKey) : null;
  if(apiKey && !keyData && (externalFormat || String(apiKey).startsWith('sk_leo_'))){
    return res.status(401).json({ error:'API key tidak valid, sudah dicabut, atau kedaluwarsa.' });
  }
  if(externalFormat && !apiKey) return res.status(401).json({ error:'Kirim API key lewat Authorization: Bearer sk_leo_… atau x-api-key.' });
  if(keyData) tier = keyData.tier;

  const limits = getTierLimit(tier);
  if(!prompt && !file) return res.status(400).json({ error:'empty prompt' });

  const available = PROVIDERS.filter(p => p.key);
  if(!available.length){
    return res.status(500).json({
      stage:'env',
      error:'Tidak ada API key AI yang di-set',
      reason:'Semua provider kosong',
      fix:'Set CHUTES_KEY / OPENROUTER_KEY / GROQ_KEY_1 di Vercel, redeploy'
    });
  }

  const messages = [{ role:'system', content: getSystemPrompt(tier) }];
  for(const h of history){
    if(h.role && h.content) messages.push({ role: h.role, content: String(h.content).slice(0,4000) });
  }

  let userMsg = prompt || '';
  if(file && file.content){
    const fc = String(file.content).slice(0, 20000);
    userMsg += '\n\n=== FILE: ' + (file.name || 'upload') + ' ===\n```\n' + fc + '\n```\n\nAnalisa, tunjukin bug, kasih versi fixed + upgrade.';
  }
  messages.push({ role:'user', content: userMsg });

  const attempts = [];

  for(const p of available){
    for(const model of p.models){
      const body = { model: model, messages: messages, temperature: limits.temp, max_tokens: limits.max_tokens };
      try {
        const r = await fetch(p.url, {
          method:'POST',
          headers: Object.assign({ 'Content-Type':'application/json' }, p.headers(p.key)),
          body: JSON.stringify(body)
        });
        const text = await r.text();

        if(r.ok){
          try {
            const data = JSON.parse(text);
            const answer = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content || '(kosong)';
            const lower = answer.toLowerCase();
            const refused = (
              lower.includes('maaf, saya tidak bisa') ||
              lower.includes("i can't help") ||
              lower.includes('i cannot help') ||
              lower.includes('tidak dapat membantu')
            ) && answer.length < 400;

            if(refused){ attempts.push({ provider: p.name, model: model, reason: 'refusal' }); continue; }

            if(externalFormat){
              return res.json({
                id:'chatcmpl-leo-' + Date.now(),
                object:'chat.completion',
                created:Math.floor(Date.now()/1000),
                model:'leoai-' + tier,
                choices:[{ index:0, message:{ role:'assistant', content:answer }, finish_reason:'stop' }],
                answer:answer,
                provider:p.name,
                tier:tier
              });
            }
            return res.json({ answer: answer, provider: p.name, model: data.model || model, tier: tier });
          } catch(e){
            attempts.push({ provider:p.name, model:model, reason:'parse failed' });
            continue;
          }
        }
        attempts.push(explainError(r.status, text, p.name, model));
      } catch(e){
        attempts.push({ provider:p.name, model:model, reason:'network error', raw:e.message });
      }
    }
  }

  return res.status(502).json({
    stage:'all_failed',
    error:'Semua provider gagal atau menolak',
    summary:'Sudah dicoba ' + attempts.length + ' kombinasi',
    attempts: attempts
  });
}
