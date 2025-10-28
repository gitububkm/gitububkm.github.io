#!/usr/bin/env python3
"""Скрипт для генерации bcrypt хешей паролей"""
import bcrypt
import sys

def generate_hash(password):
    """Генерация bcrypt хеша для пароля"""
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode(), salt)
    return password_hash.decode()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python generate_bcrypt_hash.py <password>")
        sys.exit(1)
    
    password = sys.argv[1]
    hash_value = generate_hash(password)
    print(f"Password: {password}")
    print(f"Bcrypt Hash: {hash_value}")
    print(f"\nДобавь это значение в переменную окружения Render")

