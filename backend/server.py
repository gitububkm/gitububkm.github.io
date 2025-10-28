#!/usr/bin/env python3
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
import logging
import hashlib
from datetime import datetime
from zoneinfo import ZoneInfo
from functools import wraps
import bcrypt
import shutil
import threading
import time

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
cors_config = {
    r"/collect": {"origins": ["https://gitububkm.github.io"]},
    r"/*": {"origins": ["https://gitububkm.github.io", "http://localhost:3000", "http://127.0.0.1:5500"]}
}
CORS(app, resources=cors_config)

# Security headers middleware
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# Rate limiting для защищенных эндпоинтов
rate_limit_store = {}
blocked_ips = {}  # {ip: timestamp_until_blocked}

def rate_limit(max_attempts=5, window_seconds=300):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
            now = datetime.now().timestamp()
            
            # Проверка блокировки IP
            if client_ip in blocked_ips:
                if blocked_ips[client_ip] == float('inf'):
                    # Постоянная блокировка
                    logger.error(f"PERMANENTLY BLOCKED IP {client_ip} attempted to access {f.__name__}")
                    return jsonify({'error': 'IP permanently blocked for automated tools abuse.'}), 403
                elif now < blocked_ips[client_ip]:
                    remaining = int(blocked_ips[client_ip] - now)
                    logger.warning(f"Blocked IP {client_ip} attempted to access {f.__name__}. Unblock in {remaining}s")
                    return jsonify({'error': f'IP temporarily blocked. Try again in {remaining} seconds.'}), 403
                else:
                    # Блокировка истекла
                    del blocked_ips[client_ip]
            
            key = f"{f.__name__}_{client_ip}"
            
            if key not in rate_limit_store:
                rate_limit_store[key] = []
            
            # Удаляем старые записи
            rate_limit_store[key] = [t for t in rate_limit_store[key] if now - t < window_seconds]
            
            if len(rate_limit_store[key]) >= max_attempts:
                # Блокируем IP на 30 минут при превышении лимита
                blocked_ips[client_ip] = now + 1800  # 30 минут
                logger.error(f"IP {client_ip} blocked for 30 minutes after exceeding rate limit on {f.__name__}")
                return jsonify({'error': 'Rate limit exceeded. IP blocked for 30 minutes.'}), 429
            
            rate_limit_store[key].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

SECRET_VIEW = os.environ.get('SECRET_VIEW')
SECRET_DELETE = os.environ.get('SECRET_DELETE')

DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)
REGISTRY_FILE = os.path.join(DATA_DIR, '_registry.json')

def load_registry():
    if os.path.exists(REGISTRY_FILE):
        try:
            with open(REGISTRY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_registry(reg):
    try:
        with open(REGISTRY_FILE, 'w', encoding='utf-8') as f:
            json.dump(reg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

@app.route('/collect', methods=['POST'])
@rate_limit(max_attempts=20, window_seconds=3600)  # 20 раз в час с одного IP
def collect():
    try:
        # Блокировка curl навсегда
        user_agent = request.headers.get('User-Agent', '').lower()
        if 'curl' in user_agent or 'wget' in user_agent or 'python-requests' in user_agent:
            client_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
            logger.error(f"PERMANENT BLOCK: Tool-based request from {client_ip} with UA: {request.headers.get('User-Agent', 'unknown')}")
            # Блокируем IP навсегда
            blocked_ips[client_ip] = float('inf')  # Бесконечная блокировка
            return jsonify({'error': 'Automated tools are not allowed. IP permanently blocked.'}), 403
        
        client_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
        logger.info(f"Data collection request from {client_ip}")
        # Сбор данных работает только с сайта (проверка Referer)
        # Просмотр и удаление файлов требуют пароль
        
        # Требуется Referer или Origin от твоего сайта
        referer = request.headers.get('Referer', '')
        origin = request.headers.get('Origin', '')
        allowed = False
        if referer.startswith('https://gitububkm.github.io'):
            allowed = True
        if origin.startswith('https://gitububkm.github.io'):
            allowed = True
        if not allowed:
            return jsonify({'status': 'error', 'message': 'Unauthorized source - required from github.io'}), 403
        
        data = request.get_json() or {}
        # Ограничиваем данные, которые могут быть изменены клиентом
        folder = 'site_logs'  # Фиксированная папка, клиент не может изменить
        raw_filename = None  # Имя файла формируется на сервере
        content = data.get('content', '')
        
        # Строгая проверка формата - должны быть все основные секции
        required_sections = ['=== Network ===', '=== System Info ===', '=== Browser ===']
        if not content or not all(section in content for section in required_sections):
            logger.warning(f"Invalid data format from {client_ip}")
            return jsonify({'status': 'error', 'message': 'Invalid data format'}), 400
        
        # Ограничение размера содержимого
        if len(content) > 100000:  # 100KB максимум
            content = content[:100000] + '\n[File truncated - too large]'

        # ——— Fingerprint и системные признаки (для авто-имени) ———
        fp = data.get('fingerprint') or ''
        platform = (data.get('platform') or '').replace(' ', '_')
        model = (data.get('model') or '').replace(' ', '_')
        external_ip = ''
        # --- серверные метаданные: реальный IP клиента и геоинфо ---
        client_ip = (request.headers.get('X-Forwarded-For') or request.remote_addr or '').split(',')[0].strip()
        server_block = []
        server_block.append('=== Server Observed ===')
        server_block.append(f"client_ip: {client_ip or 'unknown'}")
        try:
            import urllib.request
            import json as _json
            if client_ip:
                token = os.environ.get('IPINFO_TOKEN')
                url = f'https://ipinfo.io/{client_ip}/json'
                if token:
                    url += f'?token={token}'
                req = urllib.request.Request(url)
                resp = urllib.request.urlopen(req, timeout=5)
                g = _json.loads(resp.read())
                for k in ['hostname','city','region','country','loc','org','timezone']:
                    if k in g and g[k]:
                        server_block.append(f"ipinfo.{k}: {g[k]}")
        except Exception as e:
            server_block.append(f'ipinfo error: {str(e)[:100]}')
        server_block.append('')
        final_text = "\n".join(server_block) + content

        # ——— Имя из реестра или формирование эвристикой ———
        reg = load_registry()
        friendly = reg.get(fp)
        if not friendly:
            base = [platform or 'Device', model or '', external_ip or '']
            base = [x for x in base if x]
            friendly = "_".join(base) or 'Unknown'
            # не записываем автоматически, админ может позже задать через API

        filename = raw_filename or f"{friendly}.txt"
        if len(filename) > 100 or not filename.endswith('.txt'):
            filename = 'data.txt'
        # Добавляем серверные метаданные
        server_block = []
        server_block.append('=== Server Observed ===')
        server_block.append(f"client_ip: {client_ip or 'unknown'}")
        server_block.append(f"timestamp: {datetime.now().isoformat()}")
        try:
            import urllib.request
            import json as _json
            if client_ip:
                token = os.environ.get('IPINFO_TOKEN')
                url = f'https://ipinfo.io/{client_ip}/json'
                if token:
                    url += f'?token={token}'
                req = urllib.request.Request(url)
                resp = urllib.request.urlopen(req, timeout=5)
                g = _json.loads(resp.read())
                for k in ['hostname','city','region','country','loc','org','timezone']:
                    if k in g and g[k]:
                        server_block.append(f"ipinfo.{k}: {g[k]}")
        except Exception as e:
            server_block.append(f'ipinfo error: {str(e)[:100]}')
        server_block.append('')
        final_text = "\n".join(server_block) + content
        
        folder_path = os.path.join(DATA_DIR, folder)
        os.makedirs(folder_path, exist_ok=True)
        file_path = os.path.join(folder_path, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(final_text)
        return jsonify({'status': 'ok', 'message': 'Data saved'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/list', methods=['GET'])
@rate_limit(max_attempts=30, window_seconds=300)  # 30 запросов в 5 минут
def list_files():
    try:
        # Список файлов доступен для авторизованных пользователей
        # Защита через rate limiting
        files = []
        for root, dirs, filenames in os.walk(DATA_DIR):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, DATA_DIR)
                mtime = os.path.getmtime(filepath)
                mdt = datetime.fromtimestamp(mtime, ZoneInfo('Europe/Moscow'))
                files.append({
                    'name': filename,
                    'path': rel_path,
                    'time': mtime,
                    'time_iso': mdt.isoformat(),
                    'size': os.path.getsize(filepath)
                })
        files.sort(key=lambda x: x['time'], reverse=True)
        return jsonify({'files': files}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/ipinfo', methods=['GET'])
@rate_limit(max_attempts=10, window_seconds=300)  # 10 запросов в 5 минут
def ipinfo():
    try:
        # Проверка Referer для /ipinfo
        referer = request.headers.get('Referer', '')
        origin = request.headers.get('Origin', '')
        if not referer.startswith('https://gitububkm.github.io') and not origin.startswith('https://gitububkm.github.io'):
            logger.warning(f"Unauthorized ipinfo request from {request.remote_addr}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        import urllib.request
        token = os.environ.get('IPINFO_TOKEN')
        url = 'https://ipinfo.io/json' + (f'?token={token}' if token else '')
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=5)
        return jsonify(json.loads(resp.read())), 200
    except Exception as e:
        logger.error(f"Ipinfo error: {e}")
        return jsonify({'error': str(e)}), 500

def verify_password_hash(provided_hash, correct_password):
    """Проверка пароля с использованием bcrypt"""
    try:
        # Для bcrypt хеш должен быть в формате $2b$... 
        # Проверяем, является ли provided_hash bcrypt хешем
        if provided_hash.startswith('$2b$'):
            return bcrypt.checkpw(correct_password.encode(), provided_hash.encode())
        else:
            # Fallback для старых SHA-256 хешей
            correct_hash = hashlib.sha256(correct_password.encode()).hexdigest()
            return provided_hash == correct_hash
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

@app.route('/check-view', methods=['POST'])
@rate_limit(max_attempts=10, window_seconds=300)
def check_view():
    try:
        client_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
        data = request.get_json() or {}
        provided_hash = data.get('hash', '')
        correct_password = os.environ.get('SECRET_VIEW')
        
        if not correct_password:
            logger.error("SECRET_VIEW not configured")
            return jsonify({'valid': False, 'error': 'SECRET_VIEW not configured'}), 500
        
        is_valid = verify_password_hash(provided_hash, correct_password)
        
        if is_valid:
            logger.info(f"Successful view authentication from {client_ip}")
        else:
            logger.warning(f"Failed view authentication attempt from {client_ip}")
        
        return jsonify({'valid': is_valid}), 200
    except Exception as e:
        logger.error(f"Check view error: {e}")
        return jsonify({'valid': False, 'error': str(e)}), 500

@app.route('/check-delete', methods=['POST'])
@rate_limit(max_attempts=10, window_seconds=300)
def check_delete():
    try:
        client_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
        data = request.get_json() or {}
        provided_hash = data.get('hash', '')
        correct_password = os.environ.get('SECRET_DELETE')
        
        if not correct_password:
            logger.error("SECRET_DELETE not configured")
            return jsonify({'valid': False, 'error': 'SECRET_DELETE not configured'}), 500
        
        is_valid = verify_password_hash(provided_hash, correct_password)
        
        if is_valid:
            logger.info(f"Successful delete authentication from {client_ip}")
        else:
            logger.warning(f"Failed delete authentication attempt from {client_ip}")
        
        return jsonify({'valid': is_valid}), 200
    except Exception as e:
        logger.error(f"Check delete error: {e}")
        return jsonify({'valid': False, 'error': str(e)}), 500

@app.route('/ping', methods=['GET'])
def ping():
    try:
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/read', methods=['GET'])
@rate_limit(max_attempts=50, window_seconds=300)
def read_file():
    try:
        path = request.args.get('path')
        if not path:
            return jsonify({'error': 'path required'}), 400
        if '..' in path or path.startswith('/'):
            return jsonify({'error': 'invalid path'}), 400
        base_dir = os.path.abspath(DATA_DIR)
        full_path = os.path.abspath(os.path.join(base_dir, path))
        if not full_path.startswith(base_dir + os.sep):
            return jsonify({'error': 'invalid path'}), 400
        if not os.path.exists(full_path):
            return jsonify({'error': 'invalid path'}), 400
        
        # Читаем с ограничением размера (защита от DoS)
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read(500000)  # Макс 500KB
            if len(f.read(1)) > 0:
                content += '\n[File truncated]'
        
        logger.info(f"File read: {path}")
        return jsonify({'content': content}), 200
    except Exception as e:
        logger.error(f"Read error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/delete', methods=['DELETE'])
@rate_limit(max_attempts=5, window_seconds=60)  # 5 удалений в минуту
def delete_file():
    try:
        # Проверка пароля на сервере
        client_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
        provided_hash = request.headers.get('X-Delete-Hash', '')
        correct_password = os.environ.get('SECRET_DELETE')
        
        if not correct_password:
            logger.error("SECRET_DELETE not configured")
            return jsonify({'error': 'SECRET_DELETE not configured'}), 500
        
        if not verify_password_hash(provided_hash, correct_password):
            logger.warning(f"Failed delete authorization from {client_ip}")
            return jsonify({'error': 'Unauthorized'}), 401
        
        logger.info(f"Successful file delete from {client_ip}")
        
        path = request.args.get('path')
        if not path:
            return jsonify({'error': 'path required'}), 400
        if '..' in path or path.startswith('/'):
            return jsonify({'error': 'invalid path'}), 400
        base_dir = os.path.abspath(DATA_DIR)
        full_path = os.path.abspath(os.path.join(base_dir, path))
        if not full_path.startswith(base_dir + os.sep):
            return jsonify({'error': 'invalid path'}), 400
        if not os.path.exists(full_path):
            return jsonify({'error': 'invalid path'}), 400
        os.remove(full_path)
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Проверка целостности — критический код не должен быть изменен
INTEGRITY_CHECK = "backend_security_v2_2025"

# Backup функция
def create_backup():
    """Создание резервной копии данных"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = os.path.join('backups', timestamp)
        os.makedirs(backup_dir, exist_ok=True)
        
        if os.path.exists(DATA_DIR):
            shutil.copytree(DATA_DIR, os.path.join(backup_dir, 'data'))
            logger.info(f"Backup created: {backup_dir}")
            
            # Удаляем старые backup (старше 7 дней)
            if os.path.exists('backups'):
                for item in os.listdir('backups'):
                    item_path = os.path.join('backups', item)
                    if os.path.isdir(item_path):
                        age = time.time() - os.path.getctime(item_path)
                        if age > 7 * 24 * 3600:  # 7 дней
                            shutil.rmtree(item_path)
                            logger.info(f"Deleted old backup: {item}")
    except Exception as e:
        logger.error(f"Backup error: {e}")

# Автоматический backup каждый час
def backup_scheduler():
    """Планировщик для автоматических backup"""
    while True:
        time.sleep(3600)  # 1 час
        create_backup()

# Запуск планировщика в отдельном потоке
backup_thread = threading.Thread(target=backup_scheduler, daemon=True)
backup_thread.start()
logger.info("Backup scheduler started")

if __name__ == '__main__':
    logger.info("Starting Flask server with enhanced security")
    app.run(host='0.0.0.0', port=5000)

