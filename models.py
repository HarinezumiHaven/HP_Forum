from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from flask import current_app

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password_hash = generate_password_hash(password)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def check_password(self, password):
        """Перевіряє чи відповідає пароль хешу"""
        return check_password_hash(self.password_hash, password)
    
    def set_password(self, password):
        """Встановлює новий пароль"""
        self.password_hash = generate_password_hash(password)
    
    def generate_token(self, expires_in=24):
        """Генерує JWT токен для користувача"""
        payload = {
            'user_id': self.id,
            'username': self.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=expires_in)
        }
        return jwt.encode(payload, current_app.config['JWT_SECRET_KEY'], algorithm='HS256')
    
    @staticmethod
    def verify_token(token):
        """Перевіряє JWT токен і повертає користувача"""
        try:
            payload = jwt.decode(token, current_app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            return User.query.get(payload['user_id'])
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def update_last_login(self):
        """Оновлює час останнього входу"""
        self.last_login = datetime.datetime.utcnow()
        db.session.commit()
    
    def deactivate(self):
        """Деактивує користувача"""
        self.is_active = False
        db.session.commit()
    
    def activate(self):
        """Активує користувача"""
        self.is_active = True
        db.session.commit()
    
    def to_dict(self, include_sensitive=False):
        """Конвертує об'єкт користувача в словник"""
        user_dict = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
        
        # Включаємо чутливі дані тільки якщо потрібно
        if include_sensitive:
            user_dict['password_hash'] = self.password_hash
            
        return user_dict
    
    @classmethod
    def create_user(cls, username, email, password):
        """Створює нового користувача з валідацією"""
        # Перевірка на існування користувача
        if cls.query.filter_by(username=username).first():
            raise ValueError('Username already exists')
        
        if cls.query.filter_by(email=email.lower()).first():
            raise ValueError('Email already exists')
        
        # Валідація даних
        if len(username.strip()) < 3:
            raise ValueError('Username must be at least 3 characters long')
        
        if len(password) < 6:
            raise ValueError('Password must be at least 6 characters long')
        
        # Створення користувача
        user = cls(
            username=username.strip(),
            email=email.strip().lower(),
            password=password
        )
        
        db.session.add(user)
        db.session.commit()
        
        return user
    
    @classmethod
    def authenticate(cls, email, password):
        """Аутентифікація користувача"""
        user = cls.query.filter_by(email=email.lower()).first()
        
        if user and user.check_password(password) and user.is_active:
            user.update_last_login()
            return user
        
        return None
    
    @classmethod
    def get_active_users(cls):
        """Повертає всіх активних користувачів"""
        return cls.query.filter_by(is_active=True).all()
    
    @classmethod
    def get_user_by_id(cls, user_id):
        """Повертає користувача за ID"""
        return cls.query.get(user_id)
    
    @classmethod
    def get_user_by_username(cls, username):
        """Повертає користувача за username"""
        return cls.query.filter_by(username=username).first()
    
    @classmethod
    def get_user_by_email(cls, email):
        """Повертає користувача за email"""
        return cls.query.filter_by(email=email.lower()).first()