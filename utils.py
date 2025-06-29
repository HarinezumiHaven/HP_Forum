import re
import jwt
from functools import wraps
from flask import request, jsonify, current_app
from models import User

def validate_email(email):
    """Валідація email адреси"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    """Валідація username"""
    if not username or len(username.strip()) < 3 or len(username.strip()) > 80:
        return False
    
    # Дозволяємо тільки букви, цифри, підкреслення та дефіси
    pattern = r'^[a-zA-Z0-9_-]+$'
    return re.match(pattern, username.strip()) is not None

def validate_password(password):
    """Валідація пароля"""
    if not password or len(password) < 6:
        return False, "Password must be at least 6 characters long"
    
    # Перевірка на наявність хоча б однієї букви та цифри
    if not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
        return False, "Password must contain at least one letter and one number"
    
    return True, "Valid password"

def sanitize_input(text):
    """Очищення введених даних"""
    if not text:
        return ""
    return text.strip()

def format_datetime(dt):
    """Форматування datetime для API відповідей"""
    if dt:
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return None

def generate_response(message, data=None, status_code=200):
    """Стандартизований формат відповіді API"""
    response = {'message': message}
    if data:
        response['data'] = data
    return jsonify(response), status_code

def handle_db_error(error):
    """Обробка помилок бази даних"""
    error_message = str(error)
    
    if 'UNIQUE constraint failed' in error_message:
        if 'username' in error_message:
            return "Username already exists"
        elif 'email' in error_message:
            return "Email already exists"
    
    return "Database error occurred"

def token_required(f):
    """Декоратор для перевірки JWT токена"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Перевіряємо заголовок Authorization
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                if auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                else:
                    token = auth_header
            except IndexError:
                return jsonify({'message': 'Token format is invalid'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            current_user = User.verify_token(token)
            if not current_user:
                return jsonify({'message': 'Token is invalid or expired'}), 401
                
            if not current_user.is_active:
                return jsonify({'message': 'Account is deactivated'}), 401
                
        except Exception as e:
            return jsonify({'message': 'Token verification failed'}), 401