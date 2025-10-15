// Год в футере
    document.getElementById('y').textContent = new Date().getFullYear();

    // Появление блоков при скролле
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('reveal'); });
    }, { threshold: .12 });
    document.querySelectorAll('.fade-up').forEach(el => io.observe(el));

    // Лёгкий «tilt»
    document.querySelectorAll('[data-tilt]').forEach(card => {
      const img = card.querySelector('.img');
      card.addEventListener('mousemove', (e) => {
        const r = card.getBoundingClientRect();
        const x = (e.clientX - r.left) / r.width - .5;
        const y = (e.clientY - r.top) / r.height - .5;
        card.style.transform = `perspective(900px) rotateX(${(-y*4).toFixed(2)}deg) rotateY(${(x*6).toFixed(2)}deg)`;
        if (img) img.style.transform = `translateY(${-6 + -y*4}px) scale(1.02)`;
      });
      card.addEventListener('mouseleave', () => {
        card.style.transform = 'perspective(900px) rotateX(0) rotateY(0)';
        if (img) img.style.transform = 'translateY(0) scale(1)';
      });
    });

    /* Автоподстановка изображений + фикс-фон (#162634), поддержка верхнего регистра */
    (function () {
      const exts = ['webp','jpg','png','jpeg','WEBP','JPG','PNG','JPEG'];
      const BG = '#162634';

      document.querySelectorAll('.card .img').forEach(el => {
        const base =
          (el.getAttribute('data-proj') ||
           el.closest('.card')?.querySelector('h2')?.textContent)?.trim();
        if (!base) return;

        let tried = [];
        (function tryLoad(i){
          if (i >= exts.length) {
            console.warn(`[assets] Не нашли картинку для "${base}". Пробовали:`, tried.join(', '));
            el.style.background = `linear-gradient(${BG}, ${BG})`; // хотя бы подложка
            return;
          }
          const url = `assets/${encodeURIComponent(base)}.${exts[i]}`;
          tried.push(url);
          const img = new Image();
          img.onload = () => {
            el.style.background = `
              center / contain no-repeat url("${url}"),
              linear-gradient(${BG}, ${BG})
            `.trim();
            el.style.setProperty('--img-bg', BG);
            el.setAttribute('aria-label', base);
          };
          img.onerror = () => tryLoad(i + 1);
          img.src = url;
        })(0);
      });
    })();

    // Gmail: выезжающая панель + автозакрытие по клику вне
    (function(){
      const toggle = document.getElementById('gmailToggle');
      const panel  = document.getElementById('gmailPanel');
      const copyBtn= document.getElementById('copyEmail');
      const email  = 'ububkmart@gmail.com';

      if(toggle && panel){
        const setOpen = (open) => {
          toggle.setAttribute('aria-expanded', open);
          panel.setAttribute('aria-hidden', String(!open));
          if(open){ panel.classList.add('open'); panel.style.maxHeight = panel.scrollHeight + 'px'; }
          else     { panel.style.maxHeight = '0px'; panel.classList.remove('open'); }
        };
        toggle.addEventListener('click', () => setOpen(toggle.getAttribute('aria-expanded') !== 'true'));
        window.addEventListener('resize', () => { if(panel.classList.contains('open')) panel.style.maxHeight = panel.scrollHeight + 'px'; });

        document.addEventListener('click', (e) => {
          const wrap = document.querySelector('.reveal-wrap');
          if(!wrap) return;
          const inside = wrap.contains(e.target);
          const open   = toggle.getAttribute('aria-expanded') === 'true';
          if(open && !inside) setOpen(false);
        });
      }

      if(copyBtn){
        copyBtn.addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(email); copyBtn.textContent = 'Скопировано ✓'; setTimeout(()=>copyBtn.textContent='Копировать', 1400); }
          catch { copyBtn.textContent = email; }
        });
      }
    })();

    // «Совершенно секретно»
    (function(){
      const openBtn = document.getElementById('secretLink');
      const modal   = document.getElementById('secretModal');
      const input   = document.getElementById('secretInput');
      const ok      = document.getElementById('secretOk');
      const cancel  = document.getElementById('secretCancel');
      const panel   = document.getElementById('secretPanel');

      function computePassword(){
        const src = document.documentElement.innerHTML;
        const digits = Array.from(src).filter(ch => ch >= '0' && ch <= '9').map(ch => ch.charCodeAt(0));
        let seed = 0 >>> 0;
        for (let i=0;i<digits.length;i++) seed = ((seed*131) + digits[i]) >>> 0;
        function rnd(){ seed = (seed*1664525 + 1013904223) >>> 0; return seed / 4294967296; }
        let v = 0 >>> 0;
        const loops = Math.min(64, (digits.length || 8) + 6);
        for (let i=0;i<loops;i++){
          const r = Math.floor(rnd()*1e6) >>> 0;
          v ^= (r & 0xffff);
          v  = (v + ((seed >>> (i%24)) & 255)) >>> 0;
          v  = Math.imul(v, 2654435761) >>> 0;
        }
        const lines = src.split('\n').length;
        v ^= Math.imul(lines, (src.length % 997)) >>> 0;
        const a=(v%7), b=(v%7), c=(v^v);
        return ((a-b)|c)+1; // всегда 1
      }

      const openModal  = () => { modal.classList.add('open'); modal.setAttribute('aria-hidden','false'); input.value=''; setTimeout(()=>input.focus(),10); };
      const closeModal = () => { modal.classList.remove('open'); modal.setAttribute('aria-hidden','true'); };

      async function tryUnlock(){
        const expected = computePassword();
        const provided = Number(input.value.trim());
        if(Number.isFinite(provided) && provided === expected){
          closeModal();
          panel.hidden = false; panel.setAttribute('aria-hidden','false');
          panel.scrollIntoView({ behavior:'smooth', block:'start' });
        } else {
          const sheet = modal.querySelector('.sheet');
          sheet.classList.remove('shake'); sheet.offsetWidth; sheet.classList.add('shake');
          input.select();
        }
      }

      if(openBtn) openBtn.addEventListener('click', (e)=>{ e.preventDefault(); openModal(); });
      if(ok)      ok.addEventListener('click', tryUnlock);
      if(input)   input.addEventListener('keydown', (e)=>{ if(e.key==='Enter') tryUnlock(); if(e.key==='Escape') closeModal(); });
      if(cancel)  cancel.addEventListener('click', closeModal);
      if(modal)   modal.addEventListener('click', (e)=>{ if(e.target === modal) closeModal(); });
    })();

    // Авто-скрытие шапки на телефоне
    (function () {
      const nav = document.querySelector('.nav');
      if (!nav) return;

      let lastY = window.pageYOffset || document.documentElement.scrollTop || 0;
      let downAcc = 0, upAcc = 0;

      const HIDE_AFTER = 16;
      const PEEK_AFTER = 8;
      const SHOW_AFTER = 70;

      function onScroll() {
        const y = window.pageYOffset || document.documentElement.scrollTop || 0;
        const dy = y - lastY;
        lastY = y < 0 ? 0 : y;

        if (y <= 0) {
          nav.classList.remove('nav--hidden', 'nav--peek');
          downAcc = upAcc = 0;
          return;
        }

        if (dy > 0) {
          downAcc += dy; upAcc = 0;
          if (downAcc > HIDE_AFTER) {
            nav.classList.add('nav--hidden');
            nav.classList.remove('nav--peek');
          }
        } else if (dy < 0) {
          upAcc += -dy; downAcc = 0;
          if (upAcc > SHOW_AFTER) {
            nav.classList.remove('nav--hidden', 'nav--peek');
          } else if (upAcc > PEEK_AFTER) {
            nav.classList.remove('nav--hidden');
            nav.classList.add('nav--peek');
          }
        }
      }

      window.addEventListener('scroll', onScroll, { passive: true });
    })();
// ===== ЛР-6: аутентификация/авторизация/сессии/MFA (демо в браузере) =====
// "БД" = localStorage. Хэш пароля = PBKDF2-SHA256, соль = random(16B).
// Токены = "псевдо-JWT": header.payload.signature (HMAC-SHA256). Access ~ 2 мин, Refresh ~ 30 мин.
// MFA = одноразовый 6-значный код "по email" (смоделировано: показываем в mock-панели).

(function(){
  // ---- Утилиты ----
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

  // PBKDF2-SHA256
  async function pbkdf2Hash(password, saltHex, iterations=100_000, dkLen=32){
    const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(h=>parseInt(h,16)));
    const bits = await crypto.subtle.deriveBits({name:'PBKDF2', hash:'SHA-256', salt, iterations}, key, dkLen*8);
    return toHex(bits);
  }

  // HMAC-SHA256
  async function hmac(keyBytes, data){
    const key = await crypto.subtle.importKey('raw', keyBytes, {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, data);
    return new Uint8Array(sig);
  }

  // Псевдо-JWT
  const JWT_SECRET = enc.encode('demo-secret-only-for-lab6'); // демо-секрет
  async function signJwt(payload, ttlSec){
    const header = { alg:'HS256', typ:'JWT' };
    const iat = now();
    const exp = iat + ttlSec;
    const body = {...payload, iat, exp};
    const headB64 = b64u.enc(enc.encode(JSON.stringify(header)));
    const payB64  = b64u.enc(enc.encode(JSON.stringify(body)));
    const data = enc.encode(`${headB64}.${payB64}`);
    const sig = await hmac(JWT_SECRET, data);
    const sigB64 = b64u.enc(sig);
    return `${headB64}.${payB64}.${sigB64}`;
  }
  async function verifyJwt(token){
    const [h,p,s] = token.split('.');
    if(!h||!p||!s) throw new Error('bad token');
    const data = enc.encode(`${h}.${p}`);
    const expect = b64u.enc(await hmac(JWT_SECRET, data));
    if (expect !== s) throw new Error('bad signature');
    const payload = JSON.parse(dec.decode(b64u.dec(p)));
    if (payload.exp < now()) throw new Error('expired');
    return payload;
  }

  // ---- "БД" ----
  const DB_USERS_KEY = 'lab6_users';         // [{username, salt, hash, role, mfaEnabled, mfaSecret?}]
  const DB_SESS_KEY  = 'lab6_sessions';      // [{sid, username, refresh, exp}]
  const CURR_KEY     = 'lab6_current';       // {username,sid,access,refresh}

  const readUsers = () => JSON.parse(localStorage.getItem(DB_USERS_KEY) || '[]');
  const writeUsers = (arr) => localStorage.setItem(DB_USERS_KEY, JSON.stringify(arr));
  const readSess  = () => JSON.parse(localStorage.getItem(DB_SESS_KEY) || '[]');
  const writeSess = (arr) => localStorage.setItem(DB_SESS_KEY, JSON.stringify(arr));
  const readCurr  = () => JSON.parse(localStorage.getItem(CURR_KEY) || 'null');
  const writeCurr = (obj) => obj ? localStorage.setItem(CURR_KEY, JSON.stringify(obj)) : localStorage.removeItem(CURR_KEY);

  // ---- UI helpers ----
  const $ = (id) => document.getElementById(id);
  const logTo = (el, msg) => { el.textContent = (el.textContent ? el.textContent+'\n' : '') + msg; };

  // ---- Рендер состояния ----
  async function renderState(){
    const state = readCurr();
    const user = state?.username || '—';
    const role = state?.role || '—';
    $('#lab6_currentUser').textContent = user;
    $('#lab6_currentRole').textContent = role;
    $('#lab6_access').textContent = state?.access ? 'выдан' : '—';
    $('#lab6_refresh').textContent = state?.refresh ? 'выдан' : '—';
  }

  // ---- Регистрация ----
  $('#r_btn')?.addEventListener('click', async ()=>{
    const u = $('#r_username').value.trim();
    const p = $('#r_password').value;
    const role = $('#r_role').value;
    const out = $('#r_log'); out.textContent = '';
    if(!u || !p) return logTo(out, 'Введите логин и пароль');

    const users = readUsers();
    if (users.some(x=>x.username===u)) return logTo(out, 'Пользователь уже существует');
    const salt = toHex(rand(16));
    const hash = await pbkdf2Hash(p, salt);
    users.push({username:u, salt, hash, role, mfaEnabled:false});
    writeUsers(users);
    logTo(out, `OK: пользователь ${u} создан, роль=${role}\nСоль=${salt}\nХэш=${hash.slice(0,16)}…`);
  });

  // ---- Логин (+ MFA) ----
  let pendingMfa = null; // {username, code, role, sid, refresh}
  $('#l_btn')?.addEventListener('click', async ()=>{
    const u = $('#l_username').value.trim();
    const p = $('#l_password').value;
    const out = $('#l_log'); out.textContent = '';
    const users = readUsers();
    const user = users.find(x=>x.username===u);
    if(!user) return logTo(out, 'Неверные учетные данные');
    const hash = await pbkdf2Hash(p, user.salt);
    if(hash !== user.hash) return logTo(out, 'Неверные учетные данные');

    // MFA
    if (user.mfaEnabled){
      const code = String(Math.floor(100000 + Math.random()*900000));
      pendingMfa = { username:u, role:user.role, code };
      $('#mfa_mock_code').textContent = code;
      logTo(out, 'MFA включена: введите одноразовый код на вкладке MFA');
      // подсветим вкладку
      document.querySelector('.lab6-tab[data-tab="mfa"]')?.click();
      return;
    }

    // Без MFA: сразу выдаём токены + сессию
    await issueSession(u, user.role);
    logTo(out, `Успешный вход: ${u}`);
    renderState();
  });

  // MFA verify
  $('#mfa_enable')?.addEventListener('click', ()=>{
    const curr = readCurr();
    const out = $('#mfa_log'); out.textContent='';
    if(!curr) return logTo(out,'Сначала войдите');
    const users = readUsers();
    const user = users.find(x=>x.username===curr.username);
    if(!user) return logTo(out,'Ошибка: пользователь не найден');
    user.mfaEnabled = true;
    writeUsers(users);
    logTo(out,'MFA включена');
  });
  $('#mfa_disable')?.addEventListener('click', ()=>{
    const curr = readCurr();
    const out = $('#mfa_log'); out.textContent='';
    if(!curr) return logTo(out,'Сначала войдите');
    const users = readUsers();
    const user = users.find(x=>x.username===curr.username);
    if(!user) return logTo(out,'Ошибка: пользователь не найден');
    user.mfaEnabled = false;
    writeUsers(users);
    logTo(out,'MFA выключена');
  });
  $('#mfa_verify')?.addEventListener('click', async ()=>{
    const out = $('#mfa_log'); out.textContent='';
    const code = $('#mfa_code_input').value.trim();
    if(!pendingMfa) return logTo(out,'Нет ожидающей MFA-сессии');
    if(code !== pendingMfa.code) return logTo(out,'Неверный код');
    await issueSession(pendingMfa.username, pendingMfa.role);
    pendingMfa = null;
    $('#mfa_mock_code').textContent = '—';
    logTo(out,'MFA подтверждена, вход выполнен');
    renderState();
  });

  // ---- Выход ----
  $('#l_logout')?.addEventListener('click', ()=>{
    const curr = readCurr();
    const out = $('#l_log'); out.textContent='';
    if(!curr) return logTo(out,'Вы уже вышли');
    // Инвалидируем текущую сессию
    const sess = readSess().filter(s => s.sid !== curr.sid);
    writeSess(sess);
    writeCurr(null);
    logTo(out,'Выход выполнен');
    renderState();
  });

  // ---- Выдача токенов/сессия ----
  async function issueSession(username, role){
    const sid = toHex(rand(12));
    const access = await signJwt({sub:username, role, sid}, 120);       // 2 мин
    const refresh = await signJwt({sub:username, role, sid, typ:'R'}, 1800); // 30 мин
    // Сохраним refresh в "БД"
    const sessions = readSess();
    const payload = JSON.parse(dec.decode(b64u.dec(access.split('.')[1])));
    const rPayload = JSON.parse(dec.decode(b64u.dec(refresh.split('.')[1])));
    sessions.push({ sid, username, refresh, exp: rPayload.exp });
    writeSess(sessions);
    writeCurr({ username, role, sid, access, refresh });
  }

  // ---- Обновление access по refresh ----
  $('#a_refresh')?.addEventListener('click', async ()=>{
    const out = $('#a_log'); out.textContent='';
    const curr = readCurr();
    if(!curr) return logTo(out,'Нет активной сессии');
    try{
      const payload = await verifyJwt(curr.refresh); // проверим refresh
      // Сверим, что такой refresh есть в "БД"
      const sessions = readSess();
      const rec = sessions.find(s=>s.sid===payload.sid && s.username===payload.sub && s.refresh===curr.refresh && s.exp>=now());
      if(!rec) return logTo(out,'Refresh недействителен');
      const access = await signJwt({sub:payload.sub, role:payload.role, sid:payload.sid}, 120);
      writeCurr({...curr, access});
      logTo(out,'Access обновлён');
      renderState();
    }catch(e){
      logTo(out,'Ошибка refresh: ' + e.message);
    }
  });

  // ---- Доступ к ресурсам ----
  async function callProtected(requiredRole){
    const out = $('#a_log'); out.textContent='';
    const curr = readCurr();
    if(!curr) return logTo(out,'401: нет токена');
    try{
      const p = await verifyJwt(curr.access);
      if (requiredRole && p.role !== requiredRole) return logTo(out,'403: недостаточно прав');
      logTo(out, `200: доступ разрешён (${requiredRole||'user'}) для ${p.sub}`);
    }catch(e){
      logTo(out,'401: токен недействителен/истёк — обновите access');
    }
  }
  $('#a_user')?.addEventListener('click', ()=>callProtected(null));
  $('#a_admin')?.addEventListener('click', ()=>callProtected('admin'));

  // ---- Смена пароля ----
  $('#p_btn')?.addEventListener('click', async ()=>{
    const out = $('#p_log'); out.textContent='';
    const curr = readCurr();
    if(!curr) return logTo(out,'Сначала войдите');
    const oldP = $('#p_old').value, newP = $('#p_new').value;
    const users = readUsers();
    const u = users.find(x=>x.username===curr.username);
    if(!u) return logTo(out,'Ошибка: пользователь не найден');
    const oldHash = await pbkdf2Hash(oldP, u.salt);
    if(oldHash !== u.hash) return logTo(out,'Неверный старый пароль');
    const newSalt = toHex(rand(16));
    const newHash = await pbkdf2Hash(newP, newSalt);
    u.salt = newSalt; u.hash = newHash;
    writeUsers(users);
    logTo(out,'Пароль изменён. Старые сессии станут недействительны.');
    // Инвалидируем все сессии пользователя
    writeSess(readSess().filter(s=>s.username!==u.username));
    // Сброс текущей
    writeCurr(null);
    renderState();
  });

  // ---- Роли (ADMIN) ----
  $('#role_set')?.addEventListener('click', async ()=>{
    const out = $('#role_log'); out.textContent='';
    const target = $('#role_user').value.trim();
    const role   = $('#role_value').value;
    const curr = readCurr();
    if(!curr) return logTo(out,'Сначала войдите');
    try {
      const p = await verifyJwt(curr.access);
      if(p.role!=='admin') return logTo(out,'403: требуется роль admin');
      const users = readUsers();
      const u = users.find(x=>x.username===target);
      if(!u) return logTo(out,'Пользователь не найден');
      u.role = role; writeUsers(users);
      logTo(out, `OK: роль пользователя ${target} = ${role}`);
    } catch(e){
      logTo(out,'401: токен недействителен/истёк');
    }
  });

  // ---- Сессии ----
  $('#s_list')?.addEventListener('click', ()=>{
    const out = $('#s_log'); out.textContent='';
    const curr = readCurr();
    if(!curr) return logTo(out,'Сначала войдите');
    const list = readSess().filter(s=>s.username===curr.username);
    logTo(out, JSON.stringify(list, null, 2));
  });
  $('#s_kill')?.addEventListener('click', ()=>{
    const out = $('#s_log'); out.textContent='';
    const curr = readCurr();
    if(!curr) return logTo(out,'Сначала войдите');
    writeSess(readSess().filter(s=>s.sid!==curr.sid));
    writeCurr(null);
    logTo(out,'Текущая сессия завершена');
    renderState();
  });
  $('#s_kill_all')?.addEventListener('click', ()=>{
    const out = $('#s_log'); out.textContent='';
    const curr = readCurr();
    if(!curr) return logTo(out,'Сначала войдите');
    writeSess(readSess().filter(s=>s.username!==curr.username));
    writeCurr(null);
    logTo(out,'Все сессии пользователя завершены');
    renderState();
  });

  // ---- Вкладки ----
  document.querySelectorAll('.lab6-tab')?.forEach(btn=>{
    btn.addEventListener('click', ()=>{
      document.querySelectorAll('.lab6-tab').forEach(b=>b.classList.remove('is-active'));
      btn.classList.add('is-active');
      const t = btn.dataset.tab;
      document.querySelectorAll('.lab6-panel').forEach(p=>{
        p.style.display = (p.dataset.panel===t) ? 'block' : 'none';
      });
    });
  });

  // Инициализация
  renderState();
})();
