#!/usr/bin/env python3
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
from datetime import datetime
from zoneinfo import ZoneInfo

app = Flask(__name__)
cors_config = {
    r"/collect": {"origins": ["https://gitububkm.github.io"]},
    r"/*": {"origins": ["https://gitububkm.github.io", "http://localhost:3000", "http://127.0.0.1:5500"]}
}
CORS(app, resources=cors_config)

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
def collect():
    try:
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
        
        # Проверяем, что content содержит данные от реального браузера
        if not content or '=== Network ===' not in content:
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
def list_files():
    try:
        # просмотр списка открыт, содержимое защищается через UI
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
def ipinfo():
    try:
        import urllib.request
        token = os.environ.get('IPINFO_TOKEN')
        url = 'https://ipinfo.io/json' + (f'?token={token}' if token else '')
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=5)
        return jsonify(json.loads(resp.read())), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/check-view', methods=['POST'])
def check_view():
    try:
        data = request.get_json() or {}
        provided_hash = data.get('hash', '')
        import hashlib
        correct_password = os.environ.get('SECRET_VIEW')
        if not correct_password:
            return jsonify({'valid': False, 'error': 'SECRET_VIEW not configured'}), 500
        correct_hash = hashlib.sha256(correct_password.encode()).hexdigest()
        return jsonify({'valid': provided_hash == correct_hash}), 200
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 500

@app.route('/check-delete', methods=['POST'])
def check_delete():
    try:
        data = request.get_json() or {}
        provided_hash = data.get('hash', '')
        import hashlib
        correct_password = os.environ.get('SECRET_DELETE')
        if not correct_password:
            return jsonify({'valid': False, 'error': 'SECRET_DELETE not configured'}), 500
        correct_hash = hashlib.sha256(correct_password.encode()).hexdigest()
        return jsonify({'valid': provided_hash == correct_hash}), 200
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 500

@app.route('/ping', methods=['GET'])
def ping():
    try:
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/read', methods=['GET'])
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
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({'content': content}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete', methods=['DELETE'])
def delete_file():
    try:
        # Проверка пароля на сервере
        provided_hash = request.headers.get('X-Delete-Hash', '')
        import hashlib
        correct_password = os.environ.get('SECRET_DELETE')
        if not correct_password:
            return jsonify({'error': 'SECRET_DELETE not configured'}), 500
        correct_hash = hashlib.sha256(correct_password.encode()).hexdigest()
        if provided_hash != correct_hash:
            return jsonify({'error': 'Unauthorized'}), 401
        
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

