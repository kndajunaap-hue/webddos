import https from 'https';
import http from 'http';
import { URL } from 'url';
import { cors, ratelimit, originGuard, validateTarget } from './_guard.js';

const CHECKS = [
  { name:'SQL Injection',          sev:'high',   re:/sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|ODBC.*Driver/i },
  { name:'XSS Reflected',          sev:'high',   re:/<script>alert\(1\)<\/script>|onerror=alert/i },
  { name:'Directory Traversal',    sev:'high',   re:/root:x:0:0:|\[fonts\].*\[extensions\]/i },
  { name:'Open Directory Listing', sev:'medium', re:/<title>Index of \//i },
  { name:'PHPInfo Exposure',       sev:'medium', re:/PHP Version|phpinfo\(\)/i },
  { name:'Git Exposure',           sev:'high',   re:/Index of.*\.git|\[core\].*repositoryformatversion/i },
  { name:'Env File Leak',          sev:'high',   re:/APP_KEY=|DB_PASSWORD=|AWS_SECRET/i },
  { name:'Server Banner Leak',     sev:'low',    re:/Apache\/\d|nginx\/\d|IIS\/\d/i }
];

const HEADER_CHECKS = [
  { name:'Missing HSTS',      sev:'medium', key:'strict-transport-security' },
  { name:'Missing CSP',       sev:'medium', key:'content-security-policy' },
  { name:'Missing X-Frame',   sev:'low',    key:'x-frame-options' },
  { name:'Missing X-Content', sev:'low',    key:'x-content-type-options' },
  { name:'Missing Referrer',  sev:'low',    key:'referrer-policy' }
];

const PROBES = ['/admin','/login','/.git/','/.env','/phpinfo.php','/wp-admin/','/api/','/backup.zip','/config.php','/?id=1%27','/?q=<script>alert(1)</script>','/../../etc/passwd'];

function fetchUrl(url){
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
      res.on('data',c=>{ body+=c; if(body.length>512*1024) res.destroy(); });
      res.on('end',()=>resolve({ status:res.statusCode, headers:res.headers, body }));
      res.on('error',()=>resolve({ status:0, headers:{}, body }));
    });
    req.on('error',e=>resolve({ error:e.message, headers:{}, body:'' }));
    req.on('timeout',()=>{ req.destroy(); resolve({ error:'timeout', headers:{}, body:'' }); });
    req.end();
  });
}

export default async function handler(req,res){
  if(!cors(req,res,'POST,OPTIONS')) return;
  if(!originGuard(req,res)) return;
  if(!ratelimit(req,res)) return;
  if(req.method!=='POST') return res.status(405).json({ error:'POST only' });

  const target = validateTarget(req.body?.target);
  if(!target) return res.status(400).json({ error:'invalid target' });

  const findings = [];
  const base = await fetchUrl(target);
  if(base.error){
    findings.push({ name:'Connection Failed', severity:'high', detail:base.error });
    return res.json({ findings, count:findings.length });
  }

  for(const h of HEADER_CHECKS){
    if(!base.headers[h.key]) findings.push({ name:h.name, severity:h.sev, detail:'header absen' });
  }
  if(base.headers.server) findings.push({ name:'Server Banner', severity:'low', detail:base.headers.server });

  const results = await Promise.all(PROBES.map(p => fetchUrl(target.replace(/\/$/,'') + p).then(r => ({ path:p, ...r }))));
  for(const r of results){
    for(const c of CHECKS){
      if(c.re.test(r.body)) findings.push({ name:c.name, severity:c.sev, detail:`${r.path} → ${r.status||r.error}` });
    }
  }

  const seen = new Set(), uniq = [];
  for(const f of findings){
    const k = f.name + '|' + f.detail;
    if(!seen.has(k)){ seen.add(k); uniq.push(f); }
  }

  return res.json({ findings: uniq, count: uniq.length, target });
}
