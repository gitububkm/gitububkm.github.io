    document.getElementById('y').textContent = new Date().getFullYear();
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('reveal'); });
    }, { threshold: .12 });
    document.querySelectorAll('.fade-up').forEach(el => io.observe(el));
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
    (function () {
      const exts = ['webp','jpg','png','jpeg','WEBP','JPG','PNG','JPEG'];
      const BG = '#162634';
      document.querySelectorAll('.card .img').forEach(el => {
        const base = (el.getAttribute('data-proj') || el.closest('.card')?.querySelector('h2')?.textContent)?.trim();
        if (!base) return;
        let tried = [];
        (function tryLoad(i){
          if (i >= exts.length) {
            el.style.background = `linear-gradient(${BG}, ${BG})`;
            return;
          }
          const url = `assets/${encodeURIComponent(base)}.${exts[i]}`;
          tried.push(url);
          const img = new Image();
          img.onload = () => {
            el.style.background = `center / contain no-repeat url("${url}"), linear-gradient(${BG}, ${BG})`;
            el.style.setProperty('--img-bg', BG);
            el.setAttribute('aria-label', base);
          };
          img.onerror = () => tryLoad(i + 1);
          img.src = url;
        })(0);
      });
    })();
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
    (function(){
      const a = document.getElementById('secretLink');
      const b = document.getElementById('secretModal');
      const c = document.getElementById('secretInput');
      const d = document.getElementById('secretOk');
      const e = document.getElementById('secretCancel');
      const f = document.getElementById('secretPanel');
      const g = 'secret_access_token_v1';
      const h = 'secret_rate_limiter_v1';
      const i = () => { b.classList.add('open'); b.setAttribute('aria-hidden','false'); c.value=''; setTimeout(()=>c.focus(),10); };
      const j = () => { b.classList.remove('open'); b.setAttribute('aria-hidden','true'); };
      const k = () => { try { return JSON.parse(localStorage.getItem(h)||'{}')||{}; } catch { return {}; } };
      const l = (v) => { localStorage.setItem(h, JSON.stringify(v)); };
      function m(){ return Date.now(); }
      function n(s){ const x = Math.min(30000, (s.backoff||500)*2); const y = Math.floor(Math.random()*400); return x + y; }
      function o(){ const r = k(); const t = m(); if (r.lockUntil && t < r.lockUntil) return { allowed:false, wait: r.lockUntil - t }; return { allowed:true }; }
      function p(){ const r = k(); r.attempts = (r.attempts||0) + 1; if (r.attempts % 5 === 0){ const d = n(r); r.backoff = d; r.lockUntil = m() + d; } l(r); }
      function q(){ localStorage.removeItem(h); }
      function r(){ f.hidden = false; f.setAttribute('aria-hidden','false'); f.scrollIntoView({ behavior:'smooth', block:'start' }); }
      function s(){ return !!sessionStorage.getItem(g); }
      async function t(x){ const enc = new TextEncoder(); const buf = await crypto.subtle.digest('SHA-256', enc.encode(x)); const arr = Array.from(new Uint8Array(buf)); return arr.map(b=>b.toString(16).padStart(2,'0')).join(''); }
      function u(){ const u1=[53,58,45,44,59,59,55,68,52,57,50]; const y=53; return String.fromCharCode.apply(null, u1.map(v=>v+y)); }
      let v; (async()=>{ v = await t(u()); })();
      if (s()) r();
      async function w(){
        const x = c.value;
        const gate = o();
        if(!x){ const sh = b.querySelector('.sheet'); sh.classList.remove('shake'); sh.offsetWidth; sh.classList.add('shake'); c.select(); return; }
        if(!gate.allowed){ const sh = b.querySelector('.sheet'); sh.classList.remove('shake'); sh.offsetWidth; sh.classList.add('shake'); return; }
        await new Promise(rr=>setTimeout(rr, Math.floor(Math.random()*300)+100));
        try{
          const hp = await t(x);
          if (!v) v = await t(u());
          if(hp !== v) throw new Error('x');
          sessionStorage.setItem(g, '1');
          q();
          j();
          r();
        }catch{
          p();
          const sh = b.querySelector('.sheet');
          sh.classList.remove('shake'); sh.offsetWidth; sh.classList.add('shake');
          c.select();
        }
      }
      if(a) a.addEventListener('click', (ev)=>{ ev.preventDefault(); i(); });
      if(d) d.addEventListener('click', w);
      if(c) c.addEventListener('keydown', (ev)=>{ if(ev.key==='Enter') w(); if(ev.key==='Escape') j(); });
      if(e) e.addEventListener('click', j);
      if(b) b.addEventListener('click', (ev)=>{ if(ev.target === b) j(); });
    })();
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
        if (y <= 0) { nav.classList.remove('nav--hidden', 'nav--peek'); downAcc = upAcc = 0; return; }
        if (dy > 0) { downAcc += dy; upAcc = 0; if (downAcc > HIDE_AFTER) { nav.classList.add('nav--hidden'); nav.classList.remove('nav--peek'); } }
        else if (dy < 0) { upAcc += -dy; downAcc = 0; if (upAcc > SHOW_AFTER) { nav.classList.remove('nav--hidden', 'nav--peek'); } else if (upAcc > PEEK_AFTER) { nav.classList.remove('nav--hidden'); nav.classList.add('nav--peek'); } }
      }
      window.addEventListener('scroll', onScroll, { passive: true });
    })();
