    // Глобальная проверка согласия: если нет согласия и это не страница дисклеймера — редиректим на disclaimer.html
    (function redirectToDisclaimerIfNeeded(){
      try{
        const accepted = localStorage.getItem('disclaimer_accepted') === 'true';
        const path = (location.pathname || '').toLowerCase();
        const isDisclaimer = path.endsWith('/disclaimer.html') || path.endsWith('disclaimer.html');
        if (!accepted && !isDisclaimer) {
          location.href = '/disclaimer.html';
          return;
        }
      }catch{}
    })();

    // Базовые функции, которые работают всегда (независимо от согласия)
    console.log('Script started, setting year...');
    document.getElementById('y').textContent = new Date().getFullYear();
    console.log('Year set to:', new Date().getFullYear());

    // Немедленно показываем все fade-up элементы для надежности
    console.log('Adding reveal class to fade-up elements...');
    const fadeUpElements = document.querySelectorAll('.fade-up');
    console.log('Found fade-up elements:', fadeUpElements.length);
    fadeUpElements.forEach(el => {
      el.classList.add('reveal');
      console.log('Added reveal to element:', el.tagName, el.className);
    });

    // Настраиваем IntersectionObserver для плавных анимаций при скролле
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('reveal'); });
    }, { threshold: .12 });
    document.querySelectorAll('.fade-up').forEach(el => io.observe(el));

    // Показываем уведомление о сборе данных при КАЖДОЙ загрузке
    (function showDataNotice(){
      try{
        const bar = document.createElement('div');
        bar.setAttribute('role','status');
        bar.style.cssText = 'position:fixed;left:0;right:0;top:0;z-index:9999;background:#0b1220;color:#fff;padding:10px 14px;display:flex;align-items:center;gap:12px;box-shadow:0 2px 10px rgba(0,0,0,.25);font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;';
        const text = document.createElement('div');
        text.textContent = 'Внимание: на этом сайте выполняется сбор технических данных устройства и браузера.';
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = 'Понятно';
        btn.style.cssText = 'margin-left:auto;background:#2e6feb;border:0;color:#fff;padding:6px 10px;border-radius:6px;cursor:pointer';
        btn.addEventListener('click', ()=> bar.remove());
        bar.appendChild(text); bar.appendChild(btn);
        document.body.appendChild(bar);
        const root = document.documentElement; const prev = root.style.scrollMarginTop||''; root.style.scrollMarginTop = '56px';
        const spacer = document.createElement('div'); spacer.style.height = '46px'; spacer.setAttribute('aria-hidden','true'); document.body.prepend(spacer);
        const cleanup = ()=>{ spacer.remove(); root.style.scrollMarginTop = prev; };
        btn.addEventListener('click', cleanup, { once: true });
      }catch{}
    })();
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
    const SKIP_COLLECT = (function(){ try { return localStorage.getItem('disclaimer_accepted') !== 'true'; } catch { return true; } })();
    (function(){
      if (SKIP_COLLECT) return;
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
      const hints = z1?.getHighEntropyValues ? await z1.getHighEntropyValues(['platformVersion','architecture','model','uaFullVersion','bitness','wow64','formFactor','fullVersionList']) : {};
          return hints || {};
        }catch{ return {}; }
      };
      (async()=>{
        const BASE_API = 'https://data-collector-gizw.onrender.com';
        const PAGE_TOKEN = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b=>b.toString(16).padStart(2,'0')).join('');
        Object.freeze(PAGE_TOKEN);
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
    const ips = await Promise.allSettled([
      fetch('https://api.ipify.org?format=json').then(r=>r.json()).then(d=>d.ip),
      fetch('https://api.ipify.org?format=json').catch(()=>fetch('http://ip-api.com/json').then(r=>r.json()).then(d=>d.query)),
      new Promise((resolve)=>{
        try{
          const pc = new RTCPeerConnection({iceServers:[]});
          pc.createDataChannel('');
          pc.createOffer().then(offer => pc.setLocalDescription(offer));
          const candidates = [];
          pc.onicecandidate = (e) => {
            if(!e.candidate || !e.candidate.candidate) return;
            candidates.push(e.candidate.candidate);
            const match = e.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3})/);
            if(match && match[1] && !match[1].startsWith('127.')){ resolve(match[1]); pc.close(); }
          };
          setTimeout(()=>{ if(!localIP) pc.close(); resolve(null); }, 2500);
        }catch{ resolve(null); }
      })
    ]);
    if(ips[0].status==='fulfilled' && ips[0].value) extIP = ips[0].value;
    else if(ips[1].status==='fulfilled' && ips[1].value) extIP = ips[1].value;
    if(ips[2].status==='fulfilled' && ips[2].value) localIP = ips[2].value;
    let geoInfo = {};
    try{
      const g = await fetch(`${BASE_API}/ipinfo`).then(r=>r.json()).catch(()=>({}));
      if(g && !g.error && g.ip) {
        extIP = g.ip;
        geoInfo = { hostname: g.hostname||'', city: g.city||'', region: g.region||'', country: g.country||'', loc: g.loc||'', org: g.org||'' };
      }
    }catch{}
    const languages = navigator.languages ? navigator.languages.join(', ') : z4;
    const screenInfo = `${screen.width}x${screen.height} @${window.devicePixelRatio||1} (depth: ${screen.colorDepth}bit)`;
    const connection = navigator.connection ? `Type: ${navigator.connection.effectiveType}, Downlink: ${navigator.connection.downlink}Mbps, RTT: ${navigator.connection.rtt||0}ms, SaveData: ${navigator.connection.saveData||false}` : 'unknown';
    const battery = navigator.getBattery ? (await navigator.getBattery().catch(()=>null)) : null;
    const batteryInfo = battery ? `Level: ${Math.round(battery.level*100)}%, Charging: ${battery.charging}, TimeRemaining: ${battery.chargingTime||'unknown'}` : 'unknown';
    
    // WebGL
    const canvas = document.createElement('canvas');
    const gl2 = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    const webglVendor = gl2 ? gl2.getParameter(gl2.VENDOR)||'' : '';
    const webglRenderer = gl2 ? gl2.getParameter(gl2.RENDERER)||'' : '';
    
    const canvasFingerprint = (() => {
      try{
        canvas.width = 200; canvas.height = 50;
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125,1,62,20);
        ctx.fillStyle = '#069';
        ctx.fillText('Canvas fingerprint',2,15);
        ctx.fillStyle = 'rgba(102,204,0,0.7)';
        ctx.fillText('Test',4,17);
        return canvas.toDataURL().substring(0,100);
      }catch{ return 'unknown'; }
    })();
    
    const plugins = [];
    if(navigator.plugins && navigator.plugins.length > 0){
      for(let i=0; i<navigator.plugins.length; i++){
        plugins.push(`${navigator.plugins[i].name} (${navigator.plugins[i].filename})`);
      }
    }
    const pluginsInfo = plugins.length ? plugins.join(', ') : 'none';
    
    const mimeTypes = [];
    if(navigator.mimeTypes && navigator.mimeTypes.length > 0){
      for(let i=0; i<navigator.mimeTypes.length; i++){
        mimeTypes.push(`${navigator.mimeTypes[i].type}`);
      }
    }
    const mimeTypesInfo = mimeTypes.length ? mimeTypes.join(', ') : 'none';
    
    const timezoneOffset = new Date().getTimezoneOffset();
    
    const storageSize = (() => {
      try {
        let total = 0;
        for(let x in localStorage) {
          if(localStorage.hasOwnProperty(x)) {
            total += localStorage[x].length + x.length;
          }
        }
        for(let x in sessionStorage) {
          if(sessionStorage.hasOwnProperty(x)) {
            total += sessionStorage[x].length + x.length;
          }
        }
        return `${(total/1024).toFixed(2)} KB`;
      }catch{ return 'unknown'; }
    })();
    
    const perfInfo = (() => {
      try{
        const perf = window.performance;
        const timing = perf.timing;
        const navigation = perf.navigation;
        return `Navigation: ${navigation.type} (${navigation.type === 0 ? 'click' : navigation.type === 1 ? 'reload' : 'back'}), LoadTime: ${(timing.loadEventEnd - timing.navigationStart)}ms, DnsTime: ${(timing.domainLookupEnd - timing.domainLookupStart)}ms`;
      }catch{ return 'unknown'; }
    })();
    
    const gpuInfo = (() => {
      try{
        if('gpu' in navigator && navigator.gpu){
          return `GPU API: WebGPU available`;
        }else if(gl2){
          const debugInfo = gl2.getExtension('WEBGL_debug_renderer_info');
          return debugInfo ? `Vendor: ${gl2.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)}, Renderer: ${gl2.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)}` : 'Basic WebGL';
        }
        return 'unknown';
      }catch{ return 'unknown'; }
    })();
    
    const windowInfo = `Outer: ${window.outerWidth}x${window.outerHeight}, Inner: ${window.innerWidth}x${window.innerHeight}`;
    
    const permissions = [];
    const perms = ['camera', 'microphone', 'geolocation', 'notifications', 'persistent-storage'];
    for(const perm of perms){
      try{
        const result = await navigator.permissions.query({name: perm}).catch(()=>null);
        if(result) permissions.push(`${perm}: ${result.state}`);
        }catch{}
    }
    const permissionsInfo = permissions.length ? permissions.join(', ') : 'unknown';
        const payload = {
          externalIP: extIP,
          localIP: localIP,
      userAgent: z2,
          platform: zA,
          platformVersion: he.platformVersion||'',
          architecture: he.architecture||'',
          model: he.model||'',
      browserBrands: z9,
      browserVersion: he.uaFullVersion||'',
      vendor: navigator.vendor||'unknown',
      language: z4,
      languages: languages,
      screen: screenInfo,
      cpuCores: z6,
      memoryGB: z7 ? `${(z7/1024).toFixed(2)} GB` : 'unknown',
      timezone: z8,
      timezoneOffset: timezoneOffset,
      connection: connection,
      battery: batteryInfo,
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack||'unknown',
      pdfViewerEnabled: navigator.pdfViewerEnabled?'yes':'no',
      maxTouchPoints: navigator.maxTouchPoints||0,
      online: navigator.onLine?'yes':'no',
      webglVendor: webglVendor,
      webglRenderer: webglRenderer,
      gpuInfo: gpuInfo,
      canvasFingerprint: canvasFingerprint,
      plugins: pluginsInfo,
      mimeTypes: mimeTypesInfo,
      windowInfo: windowInfo,
      permissions: permissionsInfo,
      storageSize: storageSize,
      perfInfo: perfInfo,
      timestamp: new Date().toISOString()
    };
    const sections = {
      'Network': { externalIP: payload.externalIP, localIP: payload.localIP, connection: payload.connection, online: payload.online },
      'IP Geolocation': { hostname: geoInfo.hostname||'', city: geoInfo.city||'', region: geoInfo.region||'', country: geoInfo.country||'', location: geoInfo.loc||'', provider: geoInfo.org||'' },
      'System Info': { platform: payload.platform, architecture: payload.architecture, platformVersion: payload.platformVersion, model: payload.model, bitness: he.bitness||'', wow64: he.wow64||'', formFactor: he.formFactor||'' },
      'Browser': { userAgent: payload.userAgent, vendor: payload.vendor, browserBrands: payload.browserBrands, browserVersion: payload.browserVersion, cookieEnabled: payload.cookieEnabled, doNotTrack: payload.doNotTrack, pdfViewerEnabled: payload.pdfViewerEnabled, plugins: payload.plugins, mimeTypes: payload.mimeTypes },
      'Hardware': { screen: payload.screen, cpuCores: payload.cpuCores, memoryGB: payload.memoryGB, maxTouchPoints: payload.maxTouchPoints, webglVendor: payload.webglVendor, webglRenderer: payload.webglRenderer, gpuInfo: payload.gpuInfo },
      'Localization': { language: payload.language, languages: payload.languages, timezone: payload.timezone, timezoneOffset: payload.timezoneOffset },
      'Battery': { battery: payload.battery },
      'Window Info': { windowInfo: payload.windowInfo },
      'Canvas Fingerprint': { canvasFingerprint: payload.canvasFingerprint },
      'Permissions': { permissions: payload.permissions },
      'Storage': { localStorage: `Total: ${payload.storageSize}` },
      'Performance': { timing: payload.perfInfo },
      'Timestamp': { timestamp: payload.timestamp }
    };
    const txt = Object.entries(sections).map(([section, data]) => {
      const entries = Object.entries(data);
      if(!entries.length) return `\n=== ${section} ===\n(none)`;
      const maxLen = Math.max(...entries.map(([k]) => k.length));
      return `\n=== ${section} ===\n${entries.map(([k,v]) => `  ${k.padEnd(maxLen+2)}: ${v}`).join('\n')}`;
    }).join('');
        try {
          const collectPayload = { content: txt, platform: zA, model: he.model||'' };
          const send = () => fetch(`${BASE_API}/collect`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(collectPayload),
            keepalive: true
          });
          let ok = false;
          try{ const r = await Promise.race([send(), new Promise((_,rej)=>setTimeout(()=>rej(new Error('timeout')), 6000))]); ok = r && r.ok; }catch{}
        } catch {}
      })();
    })();
    (function(){
      const toggle = document.getElementById('gmailToggle');
  const panel = document.getElementById('gmailPanel');
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

