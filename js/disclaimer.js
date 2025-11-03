// JavaScript для страницы уведомления о конфиденциальности

// Устанавливаем текущий год
document.getElementById('y').textContent = new Date().getFullYear();

// Проявляем fade-up анимации
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.fade-up').forEach(el => el.classList.add('reveal'));
});

// Обработчики кнопок
document.getElementById('acceptBtn').addEventListener('click', function() {
  try {
    // Сохраняем согласие пользователя
    localStorage.setItem('disclaimer_accepted', 'true');
    // Перенаправляем на главную страницу
    window.location.href = '/';
  } catch (e) {
    alert('Ошибка сохранения настроек. Возможно, localStorage отключен.');
  }
});

document.getElementById('declineBtn').addEventListener('click', function() {
  // Показываем сообщение о несогласии
  document.getElementById('declineMessage').style.display = 'block';
  // Скрываем кнопки
  document.getElementById('acceptBtn').style.display = 'none';
  document.getElementById('declineBtn').style.display = 'none';
});
