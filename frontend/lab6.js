
(function () {
  const NS = 'lab6.v1';
  const ACCESS_TTL_MS  = 1000 * 60 * 5;
  const REFRESH_TTL_MS = 1000 * 60 * 60 * 24;

  const enc = new TextEncoder();
  function now() { return Date.now(); }

  function toHex(buf) {
    const b = new Uint8Array(buf);
    return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
  }

  function fromHex(hex) {
    if (!hex) return new Uint8Array();
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function rid(len = 32) {
    const b = new Uint8Array(len);
    crypto.getRandomValues(b);
    return toHex(b);
  }

  async function pbkdf2(password, saltHex, iters = 120000) {
    const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const salt = fromHex(saltHex);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iters }, key, 256);
    return toHex(bits);
  }

  function readDB() {
    const raw = localStorage.getItem(NS);
    return raw ? JSON.parse(raw) : { users: [], sessions: {}, lastMFA: null };
  }
  function writeDB(db) { localStorage.setItem(NS, JSON.stringify(db)); }

  function getUser(db, username) { return db.users.find(u => u.username === username); }

  function ensureUserIndex(db, username) {
    const i = db.users.findIndex(u => u.username === username);
    if (i < 0) throw new Error('Пользователь не найден');
    return i;
  }

  function makeToken(payload) {
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
    const body   = btoa(JSON.stringify(payload)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
    const sig    = rid(16);
    return `${header}.${body}.${sig}`;
  }

  function parseAccess(access) {
    try {
      const parts = access.split('.');
      if (parts.length < 2) return null;
      const body = JSON.parse(atob(parts[1].replaceAll('-','+').replaceAll('_','/')));
      return body;
    } catch { return null; }
  }

  function setCurrentSession(session) {
    if (!session) localStorage.removeItem(NS + '.current');
    else localStorage.setItem(NS + '.current', JSON.stringify(session));
  }
  function getCurrentSession() {
    const raw = localStorage.getItem(NS + '.current');
    return raw ? JSON.parse(raw) : null;
  }

  function requireLogged() {
    const cur = getCurrentSession();
    if (!cur) throw new Error('Нет активной сессии');
    return cur;
  }

  const LAB6 = {
    async register(username, password, role = 'user') {
      username = String(username || '').trim();
      if (!username || !password) throw new Error('Введите логин и пароль');

      const db = readDB();
      if (getUser(db, username)) throw new Error('Пользователь уже существует');

      const salt = rid(16);
      const hash = await pbkdf2(password, salt);
      db.users.push({ username, salt, hash, role: role === 'admin' ? 'admin' : 'user', mfa: false, mfaSecret: null, sessions: [] });
      writeDB(db);
      return true;
    },

    async login(username, password) {
      const db = readDB();
      const user = getUser(db, username);
      if (!user) throw new Error('Неверные логин или пароль');

      const calc = await pbkdf2(password, user.salt);
      if (calc !== user.hash) throw new Error('Неверные логин или пароль');

      if (user.mfa) {
        const code = (Math.floor(Math.random() * 1_000_000)).toString().padStart(6, '0');
        db.lastMFA = { username, code, ts: now() };
        writeDB(db);
        setCurrentSession({ pending: true, username }); // временная отметка
        return 'mfa';
      } else {
        const sid = rid(16);
        const access  = makeToken({ sub: username, role: user.role, sid, exp: now() + ACCESS_TTL_MS });
        const refresh = makeToken({ sub: username, sid, exp: now() + REFRESH_TTL_MS, type: 'refresh' });
        const session = { sid, username, role: user.role, access, refresh, accessExp: now() + ACCESS_TTL_MS, refreshExp: now() + REFRESH_TTL_MS };
        db.sessions[sid] = { ...session };
        user.sessions.push(sid);
        writeDB(db);
        setCurrentSession({ sid, username, role: user.role, access, refresh });
        return 'ok';
      }
    },

    peekMFACode() {
      const db = readDB();
      return db.lastMFA?.code || null;
    },

    async verifyMFA(code) {
      const db = readDB();
      const cur = getCurrentSession();
      if (!cur?.pending) throw new Error('Нет MFA-процесса');

      const info = db.lastMFA;
      if (!info || info.username !== cur.username) throw new Error('MFA не запрошена');
      if (!/^\d{6}$/.test(code) || code !== info.code) throw new Error('Неверный код');
      if (now() - info.ts > 5 * 60 * 1000) throw new Error('Код истёк');

      const user = getUser(db, info.username);
      const sid = rid(16);
      const access  = makeToken({ sub: user.username, role: user.role, sid, exp: now() + ACCESS_TTL_MS });
      const refresh = makeToken({ sub: user.username, sid, exp: now() + REFRESH_TTL_MS, type: 'refresh' });
      db.sessions[sid] = { sid, username: user.username, role: user.role, access, refresh, accessExp: now() + ACCESS_TTL_MS, refreshExp: now() + REFRESH_TTL_MS };
      user.sessions.push(sid);
      db.lastMFA = null;
      writeDB(db);
      setCurrentSession({ sid, username: user.username, role: user.role, access, refresh });
      return true;
    },

    current() {
      const cur = getCurrentSession();
      if (!cur) return null;
      return { ...cur, access: !!cur.access, refresh: !!cur.refresh };
    },

    async refresh() {
      const cur = requireLogged();
      const db = readDB();
      const s = db.sessions[cur.sid];
      if (!s) throw new Error('Сессия не найдена');
      if (now() > s.refreshExp) { this.logout(); throw new Error('Refresh истёк, войдите снова'); }

      s.access = makeToken({ sub: s.username, role: s.role, sid: s.sid, exp: now() + ACCESS_TTL_MS });
      s.accessExp = now() + ACCESS_TTL_MS;
      writeDB(db);
      setCurrentSession({ sid: s.sid, username: s.username, role: s.role, access: s.access, refresh: s.refresh });
      return 'Access обновлён';
    },

    async call(scope /* 'user' | 'admin' */) {
      const cur = requireLogged();
      const db = readDB();
      const s = db.sessions[cur.sid];
      if (!s) throw new Error('Нет сессии');

      const payload = parseAccess(s.access);
      if (!payload || now() > s.accessExp) throw new Error('Access истёк — обновите');

      if (scope === 'admin' && payload.role !== 'admin') throw new Error('Недостаточно прав');
      return `Доступ к ресурсу "${scope}" разрешён пользователю ${payload.sub}`;
    },

    async changePassword(oldPass, newPass) {
      const cur = requireLogged();
      const db = readDB();
      const idx = ensureUserIndex(db, cur.username);
      const user = db.users[idx];

      const check = await pbkdf2(oldPass, user.salt);
      if (check !== user.hash) throw new Error('Старый пароль неверен');

      const salt = rid(16);
      const hash = await pbkdf2(newPass, salt);
      user.salt = salt; user.hash = hash;

      (user.sessions || []).forEach(sid => { delete db.sessions[sid]; });
      user.sessions = [];
      writeDB(db);
      this.logout();
      return 'OK: пароль обновлён, войдите снова';
    },

    async setMFA(on) {
      const cur = requireLogged();
      const db = readDB();
      const idx = ensureUserIndex(db, cur.username);
      db.users[idx].mfa = !!on;
      writeDB(db);
      return 'OK: MFA ' + (on ? 'включена' : 'выключена');
    },

    async setRole(username, role) {
      const cur = requireLogged();
      const db = readDB();
      const me = getUser(db, cur.username);
      if (me.role !== 'admin') throw new Error('Требуется роль admin');

      const idx = ensureUserIndex(db, username);
      db.users[idx].role = role === 'admin' ? 'admin' : 'user';
      writeDB(db);
      return `OK: ${username} теперь ${db.users[idx].role}`;
    },

    listSessions() {
      const cur = requireLogged();
      const db = readDB();
      const user = getUser(db, cur.username);
      const list = (user.sessions || []).map(sid => db.sessions[sid]).filter(Boolean);
      if (!list.length) return 'Сессий нет';
      return list.map(s => `sid=${s.sid.slice(0,8)}…  accessExp=${new Date(s.accessExp).toLocaleString()}  refreshExp=${new Date(s.refreshExp).toLocaleString()}`).join('\n');
    },

    killCurrent() {
      const cur = requireLogged();
      const db = readDB();
      const user = getUser(db, cur.username);
      delete db.sessions[cur.sid];
      user.sessions = (user.sessions || []).filter(x => x !== cur.sid);
      writeDB(db);
      this.logout();
    },

    killAllMine() {
      const cur = requireLogged();
      const db = readDB();
      const user = getUser(db, cur.username);
      (user.sessions || []).forEach(sid => { delete db.sessions[sid]; });
      user.sessions = [];
      writeDB(db);
      this.logout();
    },

    logout() { setCurrentSession(null); }
  };

  window.LAB6 = LAB6;

  (async function bootstrap() {
    const db = readDB();
    if (!db.users.length) {
      const salt = rid(16);
      const defaultPass = prompt('Настройка системы: введите пароль для администратора (минимум 8 символов)');
      if (!defaultPass || defaultPass.length < 8) {
        console.error('[LAB6] пароль слишком короткий, админ не создан');
        return;
      }
      const hash = await pbkdf2(defaultPass, salt);
      db.users.push({ username: 'admin', salt, hash, role: 'admin', mfa: false, mfaSecret: null, sessions: [] });
      writeDB(db);
      console.log('[LAB6] администратор создан');
    }
  })();

})();
