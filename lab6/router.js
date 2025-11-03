(function() {
  'use strict';

  const routes = {
    '': '../index.html',
    'index': '../index.html',
    'lab6/register': 'register.html',
    'lab6/login': 'login.html',
    'lab6/authentification': 'authentification.html',
    'lab6/user': 'user.html'
  };

  function handleRoute() {
    const path = window.location.pathname.replace(/^\//, '').replace(/\/$/, '') || '';
    const hash = window.location.hash;

    if (window.location.pathname.endsWith('.html')) {
      const cleanPath = window.location.pathname.replace(/\.html$/, '');
      window.history.replaceState(null, null, cleanPath + hash);
      return;
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
