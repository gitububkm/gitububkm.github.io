(function() {
  'use strict';

  const routes = {
    '': 'index.html',
    'index': 'index.html',
    'register': 'register.html',
    'login': 'login.html',
    'authentification': 'authentification.html',
    'user': 'user.html',
    'wifi': 'wifi.html'
  };

  function handleRoute() {
    const path = window.location.pathname.replace(/^\//, '').replace(/\/$/, '') || '';
    const hash = window.location.hash;

    if (window.location.pathname.endsWith('.html')) {
      const cleanPath = window.location.pathname.replace(/\.html$/, '');
      window.history.replaceState(null, null, cleanPath + hash);
      return;
    }

    if (routes[path] && path !== '' && path !== 'index') {
      // Загружаем файл для маршрута
      const filePath = routes[path];
      if (filePath && !window.location.pathname.endsWith(filePath)) {
        window.location.href = '/' + filePath + hash;
        return;
      }
    }

    if (!routes[path] && path !== '') {
      window.history.replaceState(null, null, '/' + hash);
      return;
    }
  }

  function handleLinkClick(e) {
    const href = e.target.getAttribute('href');

    if (!href) return;

    if (href.startsWith('#')) {
      return;
    }

    if (href.startsWith('http') || href.startsWith('//')) {
      return;
    }

    if (href.includes('#')) {
      e.preventDefault();
      const [path, hash] = href.split('#');
      const cleanPath = path.replace(/^\//, '').replace(/\/$/, '').replace(/\.html$/, '') || '';

      if (routes[cleanPath] || cleanPath === '') {
        window.location.href = '/' + cleanPath + (hash ? '#' + hash : '');
      } else {
        window.location.href = href;
      }
    } else {
      const cleanPath = href.replace(/^\//, '').replace(/\/$/, '').replace(/\.html$/, '') || '';
      if (routes[cleanPath] && !href.endsWith('.html')) {
        e.preventDefault();
        window.location.href = '/' + cleanPath;
      }
    }
  }

  document.addEventListener('DOMContentLoaded', function() {
    handleRoute();
    document.addEventListener('click', function(e) {
      if (e.target.tagName === 'A') {
        handleLinkClick(e);
      }
    });
  });
  window.addEventListener('popstate', handleRoute);

})();
