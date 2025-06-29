from flask import Flask, jsonify, request, redirect, url_for, session, render_template
from flask_cors import CORS
from flask_socketio import SocketIO, send
from flask_migrate import Migrate
from functools import wraps
import os
import datetime

# Import models and config
from models import db, User
from config import config

def create_app(config_name=None):
    """Application factory pattern"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'default')
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)
    cors = CORS(app, origins=app.config['CORS_ORIGINS'])
    socketio = SocketIO(app, cors_allowed_origins="*")
    
    # Create database tables (замість before_first_request)
    with app.app_context():
        db.create_all()
    
    return app, socketio

app, socketio = create_app()

# JWT Token decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            current_user = User.verify_token(token)
            if not current_user:
                return jsonify({'message': 'Token is invalid!'}), 401
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Routes

@app.route('/', methods=['GET'])
def home_page():
    return render_template("home.html")

@app.route('/login', methods=['GET'])
def login_page():
    return render_template("login.html")

@app.route('/dashboard', methods=['GET'])
def dashboard_page():
    return render_template("dashboard.html")

# API Routes

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Validate input
        if not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Username, email, and password are required'}), 400
        
        username = data['username']
        email = data['email']
        password = data['password']
        
        # Create new user using class method
        new_user = User.create_user(username, email, password)
        
        return jsonify({
            'message': 'User created successfully',
            'user': new_user.to_dict()
        }), 201
        
    except ValueError as e:
        return jsonify({'message': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error creating user: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Email and password are required'}), 400
        
        email = data['email']
        password = data['password']
        
        # Authenticate user
        user = User.authenticate(email, password)
        
        if not user:
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # Generate token
        token = user.generate_token()
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Error during login: {str(e)}'}), 500

@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    return jsonify({'user': current_user.to_dict()}), 200

@app.route('/api/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    try:
        data = request.get_json()
        
        if 'username' in data:
            username = data['username'].strip()
            if len(username) < 3 or len(username) > 80:
                return jsonify({'message': 'Username must be between 3 and 80 characters'}), 400
            
            # Check if username is taken by another user
            existing_user = User.get_user_by_username(username)
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'message': 'Username already exists'}), 400
            
            current_user.username = username
        
        if 'email' in data:
            email = data['email'].strip().lower()
            
            # Check if email is taken by another user
            existing_user = User.get_user_by_email(email)
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'message': 'Email already exists'}), 400
            
            current_user.email = email
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': current_user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error updating profile: {str(e)}'}), 500

@app.route('/api/change-password', methods=['POST'])
@token_required
def change_password(current_user):
    try:
        data = request.get_json()
        
        if not data.get('current_password') or not data.get('new_password'):
            return jsonify({'message': 'Current password and new password are required'}), 400
        
        current_password = data['current_password']
        new_password = data['new_password']
        
        # Verify current password
        if not current_user.check_password(current_password):
            return jsonify({'message': 'Current password is incorrect'}), 400
        
        # Validate new password
        if len(new_password) < 6:
            return jsonify({'message': 'New password must be at least 6 characters long'}), 400
        
        # Update password using model method
        current_user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error changing password: {str(e)}'}), 500

@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    """Get list of all users (for admin purposes)"""
    users = User.get_active_users()
    return jsonify({
        'users': [user.to_dict() for user in users]
    }), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'message': 'Internal server error'}), 500

if __name__ == "__main__":
    # Create database tables (якщо запускається напряму)
    with app.app_context():
        db.create_all()
    
    # Запуск з SocketIO для підтримки WebSocket
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)