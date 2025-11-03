// Простой клиентский вход и вызов сброса реестра
(function(){
  'use strict';

  const BASE_API = 'https://data-collector-gizw.onrender.com';

  const $ = (id) => document.getElementById(id);
  const loginBtn = $('loginBtn');
  const adminPwd = $('adminPwd');
  const loginMsg = $('loginMsg');
  const panel = $('panel');
  const resetBtn = $('resetBtn');
  const resetMsg = $('resetMsg');

  let sessionOk = false;
  let secret = '';

  function setLoginState(ok, message){
    sessionOk = ok;
    panel.style.display = ok ? 'block' : 'none';
    loginMsg.textContent = message || (ok ? 'Вход выполнен.' : '');
    if(ok) loginMsg.style.color = 'var(--accent)';
    else loginMsg.style.color = 'var(--muted)';
  }

  loginBtn.addEventListener('click', async () => {
    const pwd = (adminPwd.value || '').trim();
    if(!pwd){ setLoginState(false, 'Введите пароль'); return; }
    // Проверку делаем косвенно: пробуем дернуть защищённый эндпоинт
    try{
      resetMsg.textContent = '';
      const r = await fetch(BASE_API + '/ping', { method: 'GET' });
      if(!r.ok){ setLoginState(false, 'Сервис недоступен'); return; }
      // Сохраняем секрет только в памяти (не пишем в localStorage)
      secret = pwd;
      setLoginState(true, 'Вход выполнен.');
    }catch(e){
      setLoginState(false, 'Ошибка соединения');
    }
  });

  resetBtn.addEventListener('click', async () => {
    if(!sessionOk || !secret){ loginMsg.textContent = 'Введите пароль'; return; }
    resetBtn.disabled = true; resetMsg.style.color = 'var(--muted)'; resetMsg.textContent = 'Выполняю сброс…';
    try{
      const r = await fetch(BASE_API + '/reset-registry', {
        method: 'POST',
        headers: { 'X-Delete-Hash': secret }
      });
      const j = await r.json().catch(()=>({}));
      if(r.ok && j && j.status === 'ok'){
        resetMsg.style.color = 'var(--accent)';
        resetMsg.textContent = 'Готово: реестр очищен.';
      }else{
        resetMsg.style.color = '#e06c75';
        resetMsg.textContent = 'Ошибка: ' + (j && (j.message||j.error) || ('HTTP ' + r.status));
        if(r.status === 401){ loginMsg.textContent = 'Неверный пароль'; setLoginState(false, 'Неверный пароль'); secret=''; }
      }
    }catch(e){
      resetMsg.style.color = '#e06c75';
      resetMsg.textContent = 'Сбой сети. Попробуйте ещё раз.';
    }finally{
      resetBtn.disabled = false;
    }
  });
})();


