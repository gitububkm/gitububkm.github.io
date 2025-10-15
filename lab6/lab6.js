// ===== ЛР-6: ядро (front-only demo). БД = localStorage; крипто = WebCrypto. =====
const LAB6 = (()=> {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const now = () => Math.floor(Date.now()/1000);
  const rand = (n=16) => crypto.getRandomValues(new Uint8Array(n));
  const toHex = (buf) => Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
  const b64u = {
    enc: (bytes) => {
      let s = typeof bytes === 'string' ? btoa(bytes) : btoa(String.fromCharCode(...new Uint8Array(bytes)));
      return s.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
    },
    dec: (s) => {
      s = s.replace(/-/g,'+').replace(/_/g,'/');
      const pad = s.length%4 ? '='.repeat(4-(s.length%4)) : '';
      return Uint8Array.from(atob(s+pad), c => c.charCodeAt(0));
    }
  };
  const DB_USERS = 'lab6_users';
  const DB_SESS  = 'lab6_sessions';
  const CURR     = 'lab6_current';
  const MFA_TMP  = 'lab6_mfa_pending';
  const SECRET   = enc.encode('demo-secret-only-for-lab6'); // демонстрационный секрет

  const read = k => JSON.parse(localStorage.getItem(k) || (k===CURR ? 'null' : '[]'));
  const write = (k,v) => localStorage.setItem(k, JSON.stringify(v));
  const del = k => localStorage.removeItem(k);

  async function pbkdf2(password, saltHex, iterations=100_000, dkLen=32){
    const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h=>parseInt(h,16)));
    const bits = await crypto.subtle.deriveBits({name:'PBKDF2', hash:'SHA-256', salt, iterations}, key, dkLen*8);
    return toHex(bits);
  }
  async function hmac(keyBytes, dataBytes){
    const key = await crypto.subtle.importKey('raw', keyBytes, {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, dataBytes);
    return new Uint8Array(sig);
  }
  async function signJwt(payload, ttl){
    const header = {alg:'HS256', typ:'JWT'};
    const iat = now(), exp = iat + ttl;
    const body = {...payload, iat, exp};
    const h = b64u.enc(enc.encode(JSON.stringify(header)));
    const p = b64u.enc(enc.encode(JSON.stringify(body)));
    const sig = b64u.enc(await hmac(SECRET, enc.encode(`${h}.${p}`)));
    return `${h}.${p}.${sig}`;
  }
  async function verifyJwt(tok){
    const [h,p,s] = tok.split('.');
    if(!h||!p||!s) throw new Error('bad token');
    const sig = b64u.enc(await hmac(SECRET, enc.encode(`${h}.${p}`)));
    if(sig !== s) throw new Error('bad signature');
    const payload = JSON.parse(dec.decode(b64u.dec(p)));
    if(payload.exp < now()) throw new Error('expired');
    return payload;
  }

  function users(){ return read(DB_USERS); }
  function saveUsers(v){ write(DB_USERS, v); }

  async function register(username, password, role){
    const U = users();
    if (U.some(x=>x.username===username)) throw new Error('Пользователь уже существует');
    const salt = toHex(rand(16));
    const hash = await pbkdf2(password, salt);
    U.push({username, salt, hash, role, mfaEnabled:false});
    saveUsers(U);
    return true;
  }

  async function issueSession(username, role){
    const sid = toHex(rand(12));
    const access  = await signJwt({sub:username, role, sid}, 120);
    const refresh = await signJwt({sub:username, role, sid, typ:'R'}, 1800);
    const S = read(DB_SESS);
    const rPayload = JSON.parse(dec.decode(b64u.dec(refresh.split('.')[1])));
    S.push({sid, username, refresh, exp: rPayload.exp});
    write(DB_SESS, S);
    write(CURR, {username, role, sid, access, refresh});
  }

  async function login(username, password){
    const U = users();
    const u = U.find(x=>x.username===username);
    if(!u) throw new Error('Неверные учетные данные');
    const h = await pbkdf2(password, u.salt);
    if(h !== u.hash) throw new Error('Неверные учетные данные');

    if (u.mfaEnabled){
      // сгенерировать код и запомнить временно
      const code = String(Math.floor(100000 + Math.random()*900000));
      write(MFA_TMP, {username: u.username, role: u.role, code});
      return 'mfa';
    }
    await issueSession(u.username, u.role);
    return 'ok';
  }

  function peekMFACode(){
    const p = read(MFA_TMP);
    return p?.code || null;
  }

  async function verifyMFA(code){
    const p = read(MFA_TMP);
    if(!p) throw new Error('Нет ожидающей MFA');
    if(code !== p.code) throw new Error('Неверный код');
    del(MFA_TMP);
    await issueSession(p.username, p.role);
    return true;
  }

  function current(){ return read(CURR); }

  function logout(){
    const c = current();
    if (c){
      const S = read(DB_SESS).filter(s=>s.sid!==c.sid);
      write(DB_SESS, S);
    }
    del(CURR);
  }

  async function refresh(){
    const c = current();
    if(!c) throw new Error('Нет сессии');
    const payload = await verifyJwt(c.refresh).catch(e => { throw new Error('Refresh недействителен'); });
    const S = read(DB_SESS);
    const rec = S.find(s=>s.sid===payload.sid && s.username===payload.sub && s.refresh===c.refresh && s.exp>=now());
    if(!rec) throw new Error('Refresh недействителен');
    const access = await signJwt({sub:payload.sub, role:payload.role, sid:payload.sid}, 120);
    write(CURR, {...c, access});
    return 'Access обновлён';
  }

  async function call(requiredRole){
    const c = current();
    if(!c) throw new Error('401: нет токена');
    try {
      const p = await verifyJwt(c.access);
      if (requiredRole && p.role !== requiredRole) throw new Error('403: недостаточно прав');
      return `200: доступ для ${p.sub} (${p.role})`;
    } catch(e){
      throw new Error('401: токен недействителен/истёк — обновите access');
    }
  }

  async function changePassword(oldPass, newPass){
    const c = current(); if(!c) throw new Error('Сначала войдите');
    const U = users();
    const u = U.find(x=>x.username===c.username); if(!u) throw new Error('Пользователь не найден');
    const oldH = await pbkdf2(oldPass, u.salt);
    if(oldH !== u.hash) throw new Error('Неверный старый пароль');
    const newSalt = toHex(rand(16)), newHash = await pbkdf2(newPass, newSalt);
    u.salt = newSalt; u.hash = newHash; saveUsers(U);
    // Инвалидируем все сессии пользователя
    write(DB_SESS, read(DB_SESS).filter(s=>s.username!==u.username));
    del(CURR);
    return 'OK: пароль изменён, сессии сброшены';
  }

  async function setMFA(enable){
    const c = current(); if(!c) throw new Error('Сначала войдите');
    const U = users();
    const u = U.find(x=>x.username===c.username); if(!u) throw new Error('Пользователь не найден');
    u.mfaEnabled = !!enable; saveUsers(U);
    return 'OK: MFA ' + (enable ? 'включена' : 'выключена');
  }

  async function setRole(username, role){
    const c = current(); if(!c) throw new Error('Сначала войдите');
    const p = await verifyJwt(c.access).catch(()=>null);
    if(!p || p.role!=='admin') throw new Error('403: требуется admin');
    const U = users();
    const u = U.find(x=>x.username===username); if(!u) throw new Error('Пользователь не найден');
    u.role = role; saveUsers(U);
    return `OK: роль ${username} → ${role}`;
  }

  function listSessions(){
    const c = current(); if(!c) return '—';
    const mine = read(DB_SESS).filter(s=>s.username===c.username);
    return JSON.stringify(mine, null, 2);
  }
  function killCurrent(){
    const c = current(); if(!c) return;
    write(DB_SESS, read(DB_SESS).filter(s=>s.sid!==c.sid));
    del(CURR);
  }
  function killAllMine(){
    const c = current(); if(!c) return;
    write(DB_SESS, read(DB_SESS).filter(s=>s.username!==c.username));
    del(CURR);
  }

  return {
    register, login, verifyMFA, peekMFACode,
    current, logout, refresh, call,
    changePassword, setMFA, setRole,
    listSessions, killCurrent, killAllMine
  };
})();
