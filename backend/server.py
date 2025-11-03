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
import hmac

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

rate_limit_store = {}
blocked_ips = {}

def rate_limit(max_attempts=5, window_seconds=300):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
            now = datetime.now().timestamp()
            
            if client_ip in blocked_ips:
                if blocked_ips[client_ip] == float('inf'):
                    logger.error(f"PERMANENTLY BLOCKED IP {client_ip} attempted to access {f.__name__}")
                    return jsonify({'error': 'IP permanently blocked for automated tools abuse.'}), 403
                elif now < blocked_ips[client_ip]:
                    remaining = int(blocked_ips[client_ip] - now)
                    logger.warning(f"Blocked IP {client_ip} attempted to access {f.__name__}. Unblock in {remaining}s")
                    return jsonify({'error': f'IP temporarily blocked. Try again in {remaining} seconds.'}), 403
                else:
                    del blocked_ips[client_ip]
            
            key = f"{f.__name__}_{client_ip}"
            
            if key not in rate_limit_store:
                rate_limit_store[key] = []
            
            # Удаляем старые записи
            rate_limit_store[key] = [t for t in rate_limit_store[key] if now - t < window_seconds]
            
            if len(rate_limit_store[key]) >= max_attempts:
                blocked_ips[client_ip] = now + 1800
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

def block_automated_tools():
    """Универсальная блокировка автоматизированных инструментов"""
    user_agent = request.headers.get('User-Agent', '').lower()
    automated_tools = ['curl', 'wget', 'python-requests', 'postman', 'httpie', 'insomnia', 'httpx', 'aiohttp', 'scrapy', 'requests']
    if any(tool in user_agent for tool in automated_tools):
        client_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
        logger.error(f"PERMANENT BLOCK: Automated tool detected from {client_ip} - UA: {request.headers.get('User-Agent', 'unknown')}")
        blocked_ips[client_ip] = float('inf')
        return jsonify({'error': 'Automated tools are permanently blocked.'}), 403
    return None

def calculate_similarity(text1, text2):
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())

    if not words1 or not words2:
        return 0.0

    intersection = words1.intersection(words2)
    union = words1.union(words2)

    return (len(intersection) / len(union)) * 100.0

def generate_request_signature(data):
    """Генерация HMAC-SHA256 подписи для проверки целостности запросов"""
    secret = os.environ.get('REQUEST_SECRET', 'default-secret-CHANGE-ME-NOW')
    message = json.dumps(data, sort_keys=True)
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

def verify_request_integrity(data, provided_signature):
    """Проверка целостности запроса от GitHub фронтенда"""
    expected_signature = generate_request_signature(data)
    return hmac.compare_digest(provided_signature, expected_signature)

@app.route('/collect', methods=['POST'])
@rate_limit(max_attempts=5, window_seconds=300)
def collect():
    try:
        block_result = block_automated_tools()
        if block_result:
            return block_result

        data = request.get_json() or {}
        content = data.get('content', '')

        if not content:
            return jsonify({'status': 'error', 'message': 'No content provided'}), 400

        origin = request.headers.get('Origin', '')
        referer = request.headers.get('Referer', '')
        allowed_origins = ['https://gitububkm.github.io']

        if origin and origin not in allowed_origins:
            logger.warning(f"Invalid Origin: {origin}")
            return jsonify({'status': 'error', 'message': 'Invalid Origin'}), 403

        if referer and not referer.startswith('https://gitububkm.github.io/'):
            logger.warning(f"Invalid Referer: {referer}")
            return jsonify({'status': 'error', 'message': 'Invalid Referer'}), 403

        content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        reg = load_registry()

        if content_hash in reg.get('sent_hashes', {}):
            logger.info(f"Exact duplicate content detected: {content_hash[:16]}...")
            return jsonify({'status': 'ok', 'message': 'Duplicate ignored'}), 200

        sent_contents = reg.get('sent_contents', [])
        similarity_threshold = 70.0

        for existing_content in sent_contents[-50:]:
            if calculate_similarity(content, existing_content) >= similarity_threshold:
                logger.info(f"Similar content detected (>{similarity_threshold}% similarity), skipping...")
                return jsonify({'status': 'ok', 'message': 'Similar content ignored'}), 200
        
        client_ip = (
            request.headers.get('CF-Connecting-IP', '') or
            request.headers.get('True-Client-IP', '') or
            request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
            request.remote_addr or ''
        ).strip()
        
        if not client_ip or client_ip in ['127.0.0.1', '::1']:
            try:
                import urllib.request
                client_ip_check = urllib.request.urlopen('https://api.ipify.org', timeout=3).read().decode('utf-8').strip()
                if client_ip_check:
                    client_ip = client_ip_check
            except:
                pass
        
        server_block = []
        server_block.append('\n=== Server Enriched Data ===')
        server_block.append(f'client_ip_detected: {client_ip}')
        server_block.append(f'x_forwarded_for: {request.headers.get("X-Forwarded-For", "none")}')
        server_block.append(f'remote_addr: {request.remote_addr or "none"}')
        
        try:
            import urllib.request
            import json as _json
            token = os.environ.get('IPINFO_TOKEN', '')
            url = f'https://ipinfo.io/{client_ip}/json'
            if token:
                url += f'?token={token}'
            req = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=5)
            geo = _json.loads(resp.read())
            for key in ['hostname', 'city', 'region', 'country', 'loc', 'org', 'timezone', 'postal']:
                if key in geo and geo[key]:
                    server_block.append(f'{key}: {geo[key]}')
        except Exception as e:
            server_block.append(f'geo_error: {str(e)[:100]}')
        
        enriched_content = '\n'.join(server_block) + '\n' + content
        
        telegram_bot_token = os.environ.get('TELEGRAM_BOT_TOKEN', '')
        telegram_chat_id = os.environ.get('TELEGRAM_CHAT_ID', '')
        
        if not telegram_bot_token or not telegram_chat_id:
            logger.error("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured")
            return jsonify({'status': 'error', 'message': 'Telegram not configured'}), 500
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        platform = data.get('platform', 'unknown').replace(' ', '_')[:20]
        model = data.get('model', 'unknown').replace(' ', '_')[:20]
        filename = f"{platform}_{model}_{timestamp}.txt"
        
        try:
            import urllib.request
            import json as _json
            
            telegram_url = f'https://api.telegram.org/bot{telegram_bot_token}/sendDocument'
            
            boundary = '----WebKitFormBoundary' + os.urandom(16).hex()
            
            data_parts = []
            data_parts.append(f'--{boundary}\r\n'.encode())
            data_parts.append(b'Content-Disposition: form-data; name="chat_id"\r\n\r\n')
            data_parts.append(f'{telegram_chat_id}\r\n'.encode())
            data_parts.append(f'--{boundary}\r\n'.encode())
            data_parts.append(f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'.encode())
            data_parts.append(b'Content-Type: text/plain\r\n\r\n')
            data_parts.append(enriched_content.encode('utf-8'))
            data_parts.append(f'\r\n--{boundary}\r\n'.encode())
            
            reply_markup = {
                'inline_keyboard': [[
                    {'text': '🗑️ Удалить это сообщение', 'callback_data': 'delete_msg'}
                ]]
            }
            
            data_parts.append(b'Content-Disposition: form-data; name="reply_markup"\r\n\r\n')
            data_parts.append(_json.dumps(reply_markup).encode('utf-8'))
            data_parts.append(f'\r\n--{boundary}--\r\n'.encode())
            
            body = b''.join(data_parts)
            
            req = urllib.request.Request(
                telegram_url,
                data=body,
                headers={'Content-Type': f'multipart/form-data; boundary={boundary}'}
            )
            resp = urllib.request.urlopen(req, timeout=30)
            response_data = _json.loads(resp.read())
            
            if response_data.get('ok'):
                message_id = response_data.get('result', {}).get('message_id')
                if message_id:
                    logger.info(f"Data sent to Telegram: {filename}, message_id: {message_id}")

                reg = load_registry()
                if 'sent_hashes' not in reg:
                    reg['sent_hashes'] = {}
                if 'sent_contents' not in reg:
                    reg['sent_contents'] = []

                reg['sent_hashes'][content_hash] = datetime.now().isoformat()
                reg['sent_contents'].append(content)

                if len(reg['sent_hashes']) > 1000:
                    sorted_hashes = sorted(reg['sent_hashes'].items(), key=lambda x: x[1], reverse=True)
                    reg['sent_hashes'] = dict(sorted_hashes[:1000])

                if len(reg['sent_contents']) > 50:
                    reg['sent_contents'] = reg['sent_contents'][-50:]

                save_registry(reg)

                return jsonify({'status': 'ok', 'message': 'Data sent to Telegram'}), 200
            else:
                logger.error(f"Telegram error: {response_data}")
                return jsonify({'status': 'error', 'message': 'Failed to send to Telegram'}), 500
                
        except Exception as e:
            logger.error(f"Telegram send error: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/telegram-webhook', methods=['POST'])
def telegram_webhook():
    """Webhook для обработки callback от Telegram кнопок"""
    try:
        data = request.get_json()
        
        if 'callback_query' in data:
            callback = data['callback_query']
            callback_data = callback.get('data', '')
            message = callback.get('message', {})
            message_id = message.get('message_id')
            chat_id = message.get('chat', {}).get('id')
            
            if callback_data.startswith('delete_'):
                callback_id = callback.get('id')
                
                telegram_bot_token = os.environ.get('TELEGRAM_BOT_TOKEN', '')
                if telegram_bot_token and message_id and chat_id:
                    delete_url = f'https://api.telegram.org/bot{telegram_bot_token}/deleteMessage'
                    import urllib.request
                    import json as _json
                    
                    delete_data = {'chat_id': chat_id, 'message_id': message_id}
                    req = urllib.request.Request(
                        delete_url,
                        data=_json.dumps(delete_data).encode('utf-8'),
                        headers={'Content-Type': 'application/json'}
                    )
                    urllib.request.urlopen(req, timeout=5)
                    
                    logger.info(f"Message {message_id} deleted via button")
                
                if callback_id:
                    answer_url = f'https://api.telegram.org/bot{telegram_bot_token}/answerCallbackQuery'
                    answer_data = {'callback_query_id': callback_id, 'text': 'Сообщение удалено'}
                    req = urllib.request.Request(
                        answer_url,
                        data=_json.dumps(answer_data).encode('utf-8'),
                        headers={'Content-Type': 'application/json'}
                    )
                    urllib.request.urlopen(req, timeout=5)
                    
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/collect_old', methods=['POST'])
def collect_old():
    try:
        data = request.get_json() or {}
        content = data.get('content', '')
        
        if not content:
            return jsonify({'status': 'error', 'message': 'No content provided'}), 400

        fp = data.get('fingerprint') or ''
        platform = (data.get('platform') or '').replace(' ', '_')
        model = (data.get('model') or '').replace(' ', '_')
        external_ip = ''
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

        reg = load_registry()
        friendly = reg.get(fp)
        if not friendly:
            base = [platform or 'Device', model or '', external_ip or '']
            base = [x for x in base if x]
            friendly = "_".join(base) or 'Unknown'

        filename = raw_filename or f"{friendly}.txt"
        if len(filename) > 100 or not filename.endswith('.txt'):
            filename = 'data.txt'
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
@rate_limit(max_attempts=30, window_seconds=300)
def list_files():
    try:
        # Блокировка автоматических инструментов
        block_result = block_automated_tools()
        if block_result:
            return block_result
        provided_hash = request.headers.get('X-View-Hash', '')
        correct_password = os.environ.get('SECRET_VIEW')
        
        if not correct_password:
            logger.error("SECRET_VIEW not configured")
            return jsonify({'error': 'SECRET_VIEW not configured'}), 500
        
        if not verify_password_hash(provided_hash, correct_password):
            client_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
            logger.warning(f"Unauthorized list access attempt from {client_ip}")
            return jsonify({'error': 'Unauthorized'}), 401
        
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
@rate_limit(max_attempts=10, window_seconds=300)
def ipinfo():
    try:
        # Блокировка автоматических инструментов
        block_result = block_automated_tools()
        if block_result:
            return block_result
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

def verify_password_hash(provided_hash, correct_password_hash):
    """Проверка пароля - сравнение SHA-256 хешей"""
    try:
        return hmac.compare_digest(provided_hash, correct_password_hash)
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
        # Блокировка автоматических инструментов
        block_result = block_automated_tools()
        if block_result:
            return block_result
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
@rate_limit(max_attempts=5, window_seconds=60)
def delete_file():
    try:
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

INTEGRITY_CHECK = "backend_security_v2_2025"

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

def backup_scheduler():
    """Планировщик для автоматических backup"""
    while True:
        time.sleep(3600)
        create_backup()

backup_thread = threading.Thread(target=backup_scheduler, daemon=True)
backup_thread.start()
logger.info("Backup scheduler started")

if __name__ == '__main__':
    logger.info("Starting Flask server with enhanced security")
    app.run(host='0.0.0.0', port=5000)

