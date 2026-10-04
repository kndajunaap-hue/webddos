import https from 'https';
import http from 'http';
import { URL } from 'url';

const CHECKS = [
  { name:'SQL Injection',    severity:'high',   test:r=>/sql|mysql|syntax.*error|odbc/i.test(r) },
  { name:'XSS Reflected',    severity:'high',   test:(r,s)=>s.body&&s.body.includes('<script>alert(1)</script>') },
  { name:'Open Directory',   severity:'medium', test:r=>/Index of \//i.test(r) },
  { name:'Server Banner Leak',severity:'low',   test:(r,s)=>/Server:/i.test(s.headers) },
  { name:'Missing HSTS',     severity:'medium', test:(r,s)=>!/strict-transport-security/i.test(s.headers) },
  { name:'Missing CSP',      severity:'medium', test:(r,s)=>!/content-security-policy/i.test(s.headers) },
  { name:'X-Frame-Options Absent', severity:'low', test:(r,s)=>!/x-frame-options/i.test(s.headers) },
  { name:'Directory Traversal', severity:'high', test:r=>/root:.*:0:0:/i.test(r) },
  { name:'PHP Info Leak',    severity:'medium', test:r=>/phpinfo\(\)|PHP Version/i.test(r) },
  { name:'Git Exposure',     severity:'high',   test:r=>/Index of.*\.git/i.test(r) },
];

function fetchUrl(url, opts={}){
  return new Promise(resolve => {
    const u = new URL(url);
    const mod = u.protocol==='https:' ? https : http;
    const req = mod.request({
      hostname:u.hostname, port:u.port||(u.protocol==='https:'?443:80),
      path:u.pathname+u.search, method:'GET',
      headers:{'User-Agent':'Mozilla/5.0','Accept':'*/*'},
      rejectUnauthorized:false, timeout:8000
    }, res => {
      let body='';
      res.on('data',c=>body+=c);
      res.on('end',()=>resolve({ status:res.statusCode, headers:res.headers, body }));
    });
    req.on('error',e=>resolve({ error:e.message, body:'', headers:{} }));
    req.on('timeout',()=>{ req.destroy(); resolve({ error:'timeout', body:'', headers:{} }); });
    req.end();
  });
}

export default async function handler(req, res){
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
  if(req.method==='OPTIONS') return res.status(200).end();
  if(req.method!=='POST') return res.status(405).json({error:'POST only'});

  const { target } = req.body||{};
  if(!target) return res.status(400).json({error:'target required'});

  const findings = [];
  const base = await fetchUrl(target);

  if(base.error){
    findings.push({ name:'Connection Failed', severity:'high', detail:base.error });
    return res.json({ findings });
  }

  // probe path umum
  const probes = [
    '/admin','/login','/.git/','/.env','/phpinfo.php','/wp-admin/',
    '/api/','/backup.zip','/config.php','/?id=1%27','/?q=<script>alert(1)</script>'
  ];
  const results = await Promise.all(probes.map(p => {
    const url = target.replace(/\/$/,'') + p;
    return fetchUrl(url).then(r => ({ path:p, ...r }));
  }));

  for(const r of results){
    for(const c of CHECKS){
      try {
        if(c.test(r.body, r)) findings.push({ name:c.name, severity:c.severity, detail:`${r.path} → ${r.status||r.error}` });
      } catch(e){}
    }
  }

  // header checks pada base
  for(const c of CHECKS){
    try {
      if(!c.name.includes('Directory') && !c.name.includes('SQL') && !c.name.includes('XSS') && c.test(base.body, base)){
        findings.push({ name:c.name, severity:c.severity, detail:'base response' });
      }
    } catch(e){}
  }

  // dedupe
  const uniq = [];
  const seen = new Set();
  for(const f of findings){
    const k = f.name+f.detail;
    if(!seen.has(k)){ seen.add(k); uniq.push(f); }
  }

  return res.json({ findings: uniq, count: uniq.length });
}
