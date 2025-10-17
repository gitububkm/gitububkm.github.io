// Роутер для поддержки чистых URL на GitHub Pages
(function() {
  'use strict';

  // Карта маршрутов: чистый URL -> файл
  const routes = {
    '': 'index.html',
    'index': 'index.html',
    'register': 'register.html',
    'login': 'login.html',
    'authentification': 'authentification.html',
    'user': 'user.html'
  };

  // Функция для обработки текущего URL
  function handleRoute() {
    const path = window.location.pathname.replace(/^\//, '').replace(/\/$/, '') || '';
    const hash = window.location.hash;

    // Если это запрос к .html файлу напрямую, перенаправляем на чистый URL
    if (window.location.pathname.endsWith('.html')) {
      const cleanPath = window.location.pathname.replace(/\.html$/, '');
      window.history.replaceState(null, null, cleanPath + hash);
      return;
    }

    // Если путь не соответствует нашим маршрутам, перенаправляем на главную
    if (!routes[path] && path !== '') {
      window.history.replaceState(null, null, '/' + hash);
      return;
    }
  }

  // Обработка кликов по ссылкам
  function handleLinkClick(e) {
    const href = e.target.getAttribute('href');

    if (!href) return;

    // Обрабатываем внутренние ссылки
    if (href.startsWith('#')) {
      // Якорные ссылки обрабатываем стандартно
      return;
    }

    if (href.startsWith('http') || href.startsWith('//')) {
      // Внешние ссылки пропускаем
      return;
    }

    // Обрабатываем относительные ссылки
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
      // Простая относительная ссылка без хеша
      const cleanPath = href.replace(/^\//, '').replace(/\/$/, '').replace(/\.html$/, '') || '';
      if (routes[cleanPath] && !href.endsWith('.html')) {
        e.preventDefault();
        window.location.href = '/' + cleanPath;
      }
    }
  }

  // Инициализация
  document.addEventListener('DOMContentLoaded', function() {
    handleRoute();

    // Добавляем обработчик кликов для всех ссылок
    document.addEventListener('click', function(e) {
      if (e.target.tagName === 'A') {
        handleLinkClick(e);
      }
    });
  });

  // Обработка кнопки "Назад"
  window.addEventListener('popstate', handleRoute);

})();
