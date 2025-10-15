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