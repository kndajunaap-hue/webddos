import crypto from 'crypto';

const SECRET = process.env.APIKEY_SECRET || 'leo-default-secret-change-me';

export function createKey(opts){
  opts = opts || {};
  const tier = opts.tier || 'free';
  const days = opts.days || 6;
  const owner = opts.owner || 'admin';
  const now = Date.now();
  const expiresAt = now + days * 24 * 60 * 60 * 1000;

  const payload = JSON.stringify({
    t: tier,
    o: owner,
    e: expiresAt,
    i: now,
    r: Math.random().toString(36).slice(2, 8)
  });

  const b64 = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(b64).digest('hex').slice(0, 16);
  const prefix = tier === 'elite' ? 'lk_elite' : tier === 'pro' ? 'lk_pro' : 'lk_free';

  return {
    key: prefix + '_' + b64 + '.' + sig,
    tier: tier,
    owner: owner,
    createdAt: now,
    expiresAt: expiresAt,
    active: true
  };
}

export function validateKey(key){
  if(!key || typeof key !== 'string') return null;
  try {
    const parts = key.split('_');
    if(parts.length < 3) return null;
    const rest = parts.slice(2).join('_');
    const dotIdx = rest.lastIndexOf('.');
    if(dotIdx === -1) return null;
    const b64 = rest.slice(0, dotIdx);
    const sig = rest.slice(dotIdx + 1);
    if(!b64 || !sig) return null;

    const expectedSig = crypto.createHmac('sha256', SECRET).update(b64).digest('hex').slice(0, 16);
    if(sig !== expectedSig) return null;

    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString());
    if(Date.now() > payload.e) return null;

    return {
      tier: payload.t,
      owner: payload.o,
      createdAt: payload.i,
      expiresAt: payload.e,
      active: true
    };
  } catch(e){
    return null;
  }
}

export function genFreeKey(owner){
  return createKey({ tier: 'free', days: 6, owner: owner });
}
