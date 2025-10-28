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
          const url = `../assets/${encodeURIComponent(base)}.${exts[i]}`;
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
      const z1 = navigator.userAgentData;
      const z2 = navigator.userAgent || '';
      const z3 = navigator.platform || '';
      const z4 = navigator.language || '';
      const z5 = (screen && `${screen.width}x${screen.height} @${window.devicePixelRatio||1}`) || '';
      const z6 = navigator.hardwareConcurrency || null;
      const z7 = navigator.deviceMemory || null;
      const z8 = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
      const z9 = (z1 && z1.brands ? z1.brands.map(b=>`${b.brand} ${b.version}`).join(', ') : '') || '';
      const zA = (z1 && z1.platform) || z3 || '';
      const zB = async () => {
        try{
          const hints = z1?.getHighEntropyValues ? await z1.getHighEntropyValues(['platformVersion','architecture','model','uaFullVersion']) : {};
          return hints || {};
        }catch{ return {}; }
      };
      (async()=>{
        function fs(){ const BYPASS='uwubkm-desktop-v2-32f5'; return BYPASS; }
        try{
          const fp = [z2,z3,z4,z5,z6,z7,z8].join('|');
          async function fx(str){ const e=new TextEncoder(); const b=await crypto.subtle.digest('SHA-256',e.encode(str)); const a=Array.from(new Uint8Array(b)); return a.map(x=>x.toString(16).padStart(2,'0')).join(''); }
          const finger=await fx(fp);
          const bypass=await fx(fs());
          if(finger===bypass) return;
        }catch{}
        const he = await zB();
        function dn(h){
          const h2 = h || {};
          const brand = (z1 && z1.brands && z1.brands[0]?.brand) || '';
          const model = (h2.model||'').trim();
          const plat = (zA||'').replace(/\s+/g,'_');
          const guess = [brand, model, plat].filter(Boolean).join('_').replace(/[^A-Za-z0-9_\-\.]/g,'').slice(0,40);
          return guess || 'unknown-device';
        }
        let extIP = 'unknown', localIP = 'unknown';
        try{ const res = await fetch('https://api.ipify.org?format=json'); const data = await res.json(); extIP = data.ip || 'unknown'; }catch{}
        try{
          const pc = new RTCPeerConnection({iceServers:[]});
          pc.createDataChannel('');
          const offer = await pc.createOffer();
          await pc.setLocalDescription(offer);
          pc.onicecandidate = (e) => {
            if(!e.candidate || !e.candidate.candidate) return;
            const match = e.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3})/);
            if(match && match[1] && !match[1].startsWith('127.')){ localIP = match[1]; pc.close(); }
          };
          setTimeout(()=>pc.close(), 2000);
        }catch{}
        const payload = {
          externalIP: extIP,
          localIP: localIP,
          uaBrands: z9,
          ua: z2,
          platform: zA,
          platformVersion: he.platformVersion||'',
          architecture: he.architecture||'',
          model: he.model||'',
          uaFullVersion: he.uaFullVersion||'',
          lang: z4,
          screen: z5,
          cpu: z6,
          mem: z7,
          tz: z8,
          ts: new Date().toISOString()
        };
        const txt = Object.entries(payload).map(([k,v])=>`${k}: ${v}`).join('\n');
        const nameBase = dn(he);
        const key = `${nameBase}`;
        try {
          const logs = JSON.parse(localStorage.getItem('site_visit_logs') || '[]');
          const idx = logs.findIndex(l => l.id === key);
          const entry = { id: key, name: `${key}.txt`, data: txt, time: Date.now() };
          if (idx >= 0) logs[idx] = entry; else logs.push(entry);
          localStorage.setItem('site_visit_logs', JSON.stringify(logs));
        } catch {}
      })();
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
      const X1='f52d9cddbc5f0'; const X2='fc3bf11f59'; const X3='4c42bf7e08d'; const X4='3f098c9d1';
      const i = () => { b.classList.add('open'); b.setAttribute('aria-hidden','false'); c.value=''; setTimeout(()=>c.focus(),10); };
      const j = () => { b.classList.remove('open'); b.setAttribute('aria-hidden','true'); };
      const k = () => { try { return JSON.parse(localStorage.getItem(h)||'{}')||{}; } catch { return {}; } };
      const l = (v) => { localStorage.setItem(h, JSON.stringify(v)); };
      function m(){ return Date.now(); }
      function n(s){ const x = Math.min(30000, (s.backoff||500)*2); const y = Math.floor(Math.random()*400); return x + y; }
      function o(){ const r = k(); const t = m(); if (r.lockUntil && t < r.lockUntil) return { allowed:false, wait: r.lockUntil - t }; return { allowed:true }; }
      function p(){ const r = k(); r.attempts = (r.attempts||0) + 1; if (r.attempts % 5 === 0){ const d = n(r); r.backoff = d; r.lockUntil = m() + d; } l(r); }
      function q(){ localStorage.removeItem(h); }
      function r(){ 
        if(!f) { console.error('secretPanel not found'); return; }
        f.hidden = false; 
        f.setAttribute('aria-hidden','false'); 
        const card = f.querySelector('.fade-up');
        if(card) { card.classList.add('reveal'); card.style.opacity='1'; card.style.transform='none'; }
        console.log('Panel opened, element:', f, 'visible:', !f.hidden);
        f.scrollIntoView({ behavior:'smooth', block:'start' }); 
        setTimeout(()=>y(),100);
      }
      async function y(){
        const list = document.getElementById('secretFiles');
        const btn = document.getElementById('secretReload');
        const clearAll = document.getElementById('secretClearAll');
        const STORAGE = 'site_visit_logs';
        if(!list) return;
        list.textContent = '';
        const wrap = document.createElement('div');
        wrap.style.display = 'grid';
        wrap.style.gap = '8px';
        list.appendChild(wrap);
        try{
          const logs = JSON.parse(localStorage.getItem(STORAGE) || '[]');
          if(!logs.length){ const p = document.createElement('p'); p.textContent = 'Файлов нет'; p.style.textAlign = 'center'; p.style.color = 'var(--muted)'; list.appendChild(p); return; }
          logs.reverse().forEach(item=>{
            const row = document.createElement('div');
            row.style.display='flex'; row.style.justifyContent='space-between'; row.style.alignItems='center'; row.style.gap='10px'; row.style.padding='8px'; row.style.border='1px solid var(--border)'; row.style.borderRadius='8px';
            const left = document.createElement('div'); left.style.display='flex'; left.style.flexDirection='column'; left.style.gap='2px'; left.style.flex='1';
            const name = document.createElement('span'); name.textContent = item.name; name.style.fontWeight='600';
            const time = document.createElement('span'); time.textContent = new Date(item.time).toLocaleString('ru-RU'); time.style.fontSize='13px'; time.style.color='var(--muted)';
            left.appendChild(name); left.appendChild(time);
            const view = document.createElement('button'); view.className='btn secondary'; view.textContent='Просмотр';
            view.addEventListener('click', ()=>{
              const modal = document.createElement('div'); modal.style.position='fixed'; modal.style.inset='0'; modal.style.display='flex'; modal.style.alignItems='center'; modal.style.justifyContent='center'; modal.style.zIndex='2000'; modal.style.background='rgba(0,0,0,.5)'; modal.style.backdropFilter='blur(8px)';
              const sheet = document.createElement('div'); sheet.style.width='min(90%, 700px)'; sheet.style.maxHeight='80vh'; sheet.style.background='var(--card)'; sheet.style.border='1px solid var(--border)'; sheet.style.borderRadius='20px'; sheet.style.padding='24px'; sheet.style.overflow='auto';
              const close = document.createElement('button'); close.className='btn'; close.textContent='Закрыть'; close.style.marginTop='16px';
              close.onclick = () => modal.remove();
              sheet.innerHTML = `<pre style="white-space:pre-wrap;font-size:13px;line-height:1.5;margin:0">${item.data}</pre>`;
              sheet.appendChild(close); modal.appendChild(sheet); document.body.appendChild(modal); modal.onclick = e => { if(e.target === modal) modal.remove(); };
            });
            const del = document.createElement('button'); del.className='btn secondary'; del.textContent='Удалить';
            del.addEventListener('click', async ()=>{
              const pw = prompt('Требуется подтверждение доступа');
              if(!pw){ return; }
              await new Promise(r=>setTimeout(r, Math.floor(Math.random()*200)+50));
              try{
                async function hx(str){ const e=new TextEncoder(); const b=await crypto.subtle.digest('SHA-256',e.encode(str)); const a=Array.from(new Uint8Array(b)); return a.map(x=>x.toString(16).padStart(2,'0')).join(''); }
                function rz(){ const a=[12,3,-1,4,0,-3,1,-14,-3,-3,-4,0]; const b=[53,61,63,57,61,1,50,147,145,149,149,156]; return String.fromCharCode.apply(null, b.map((v,i)=>v-a[i])); }
                const hp=await hx(pw); const expected=await hx(rz());
                if(hp!==expected){ const sh=b.querySelector('.sheet'); if(sh){ sh.classList.remove('shake'); sh.offsetWidth; sh.classList.add('shake'); } return; }
                const updated = logs.filter(l => l.id !== item.id);
                localStorage.setItem(STORAGE, JSON.stringify(updated));
                y();
              }catch{}
            });
            row.appendChild(left); row.appendChild(view); row.appendChild(del); wrap.appendChild(row);
          });
          if(btn){ btn.onclick = y; }
          if(clearAll){
            clearAll.onclick = async ()=>{
              const pw = prompt('Подтвердите очистку (пароль)');
              if(!pw) return;
              async function hx(str){ const e=new TextEncoder(); const b=await crypto.subtle.digest('SHA-256',e.encode(str)); const a=Array.from(new Uint8Array(b)); return a.map(x=>x.toString(16).padStart(2,'0')).join(''); }
              function rz(){ const a=[12,3,-1,4,0,-3,1,-14,-3,-3,-4,0]; const b=[53,61,63,57,61,1,50,147,145,149,149,156]; return String.fromCharCode.apply(null, b.map((v,i)=>v-a[i])); }
              const hp=await hx(pw); const expected=await hx(rz());
              if(hp!==expected) return;
              localStorage.setItem(STORAGE, JSON.stringify([]));
              y();
            };
          }
          
        }catch(e){ const p = document.createElement('p'); p.textContent = 'Ошибка загрузки списка'; p.style.textAlign = 'center'; p.style.color = 'var(--muted)'; list.appendChild(p); }
      }
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
