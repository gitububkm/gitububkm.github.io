#!/usr/bin/env python3
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
from datetime import datetime

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["https://gitububkm.github.io", "http://localhost:3000", "http://127.0.0.1:5500"]}})

DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)

@app.route('/collect', methods=['POST'])
def collect():
    try:
        data = request.get_json()
        folder = data.get('folder_name', 'unknown')
        filename = data.get('file_name', f'log_{datetime.now().timestamp()}.txt')
        content = data.get('content', '')
        folder_path = os.path.join(DATA_DIR, folder)
        os.makedirs(folder_path, exist_ok=True)
        file_path = os.path.join(folder_path, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return jsonify({'status': 'ok', 'message': 'Data saved'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/list', methods=['GET'])
def list_files():
    try:
        files = []
        for root, dirs, filenames in os.walk(DATA_DIR):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, DATA_DIR)
                mtime = os.path.getmtime(filepath)
                files.append({
                    'name': filename,
                    'path': rel_path,
                    'time': mtime,
                    'size': os.path.getsize(filepath)
                })
        files.sort(key=lambda x: x['time'], reverse=True)
        return jsonify({'files': files}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/read', methods=['GET'])
def read_file():
    try:
        path = request.args.get('path')
        if not path:
            return jsonify({'error': 'path required'}), 400
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
        path = request.args.get('path')
        if not path:
            return jsonify({'error': 'path required'}), 400
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

