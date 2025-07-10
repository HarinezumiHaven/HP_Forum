from flask import Flask, jsonify, request, redirect, url_for, session, render_template
from flask_cors import CORS
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from flask_migrate import Migrate
from functools import wraps
import os
import datetime
import jwt
import logging

# Import models and config
from models import db, User, ChatMessage
from config import config
from dotenv import load_dotenv
load_dotenv() 

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app, socketio

app, socketio = create_app()

# Store active connections
active_users = {}

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
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# WebSocket token verification
def verify_socket_token(token):
    """Verify token for WebSocket connections"""
    try:
        if token and token.startswith('Bearer '):
            token = token[7:]
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(payload['user_id'])
        if user and user.is_active:
            return user
        return None
    except Exception as e:
        logger.error(f"Socket token verification error: {str(e)}")
        return None

# Pages

@app.route('/', methods=['GET'])
def home_page():
    return render_template("home.html")

@app.route('/login', methods=['GET'])
def login_page():
    return render_template("login.html")

@app.route('/navigation', methods=['GET'])
def navigation_page():
    return render_template("navigation.html")

@app.route('/g_chat', methods=['GET'])
def g_chat_page():
    return render_template("g_chat.html")

# API 

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        

        if not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Username, email, and password are required'}), 400
        
        username = data['username'].strip()
        email = data['email'].strip().lower()
        password = data['password']
        

        if len(username) < 3 or len(username) > 80:
            return jsonify({'message': 'Username must be between 3 and 80 characters'}), 400
        
        if len(password) < 6:
            return jsonify({'message': 'Password must be at least 6 characters long'}), 400
        
        # create new abuser
        new_user = User.create_user(username, email, password)
        
        logger.info(f"New user registered: {username}")
        
        return jsonify({
            'message': 'User created successfully',
            'user': new_user.to_dict()
        }), 201
        
    except ValueError as e:
        return jsonify({'message': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'message': f'Error creating user: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Email and password are required'}), 400
        
        email = data['email'].strip().lower()
        password = data['password']
        
        # check user data
        user = User.authenticate(email, password)
        
        if not user:
            return jsonify({'message': 'Invalid email or password'}), 401
        
        token = user.generate_token()
        
        logger.info(f"User logged in: {user.username}")
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
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
            
            # unic username?
            existing_user = User.get_user_by_username(username)
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'message': 'Username already exists'}), 400
            
            current_user.username = username
        
        if 'email' in data:
            email = data['email'].strip().lower()
            
            # unic email?
            existing_user = User.get_user_by_email(email)
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'message': 'Email already exists'}), 400
            
            current_user.email = email
        
        db.session.commit()
        
        logger.info(f"Profile updated for user: {current_user.username}")
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': current_user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Profile update error: {str(e)}")
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
        
        # check current password
        if not current_user.check_password(current_password):
            return jsonify({'message': 'Current password is incorrect'}), 400
        
        # create new password
        if len(new_password) < 6:
            return jsonify({'message': 'New password must be at least 6 characters long'}), 400
        
        # update password
        current_user.set_password(new_password)
        db.session.commit()
        
        logger.info(f"Password changed for user: {current_user.username}")
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Password change error: {str(e)}")
        return jsonify({'message': f'Error changing password: {str(e)}'}), 500

@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    """Get list of all active users"""
    try:
        users = User.get_active_users()
        return jsonify({
            'users': [user.to_dict() for user in users],
            'online_users': list(active_users.keys())
        }), 200
    except Exception as e:
        logger.error(f"Get users error: {str(e)}")
        return jsonify({'message': f'Error fetching users: {str(e)}'}), 500

@app.route('/api/messages', methods=['GET'])
@token_required
def get_messages(current_user):
    """Get recent chat messages"""
    try:
        limit = request.args.get('limit', 50, type=int)
        if limit > 100:
            limit = 100
        
        messages = ChatMessage.get_recent_messages(limit)
        
        return jsonify({
            'messages': [message.to_dict() for message in messages]
        }), 200
        
    except Exception as e:
        logger.error(f"Get messages error: {str(e)}")
        return jsonify({'message': f'Error fetching messages: {str(e)}'}), 500

@app.route('/api/messages/<int:message_id>', methods=['DELETE'])
@token_required
def delete_message(current_user, message_id):
    """Delete a message (soft delete)"""
    try:
        message = ChatMessage.query.get(message_id)
        
        if not message:
            return jsonify({'message': 'Message not found'}), 404
        
        # delete own msgs
        if message.user_id != current_user.id:
            return jsonify({'message': 'You can only delete your own messages'}), 403
        
        message.soft_delete()
        
        # notify all clients about message deletion
        socketio.emit('message_deleted', {
            'message_id': message_id,
            'deleted_by': current_user.username
        }, room='global_chat')
        
        logger.info(f"Message {message_id} deleted by user: {current_user.username}")
        
        return jsonify({'message': 'Message deleted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Delete message error: {str(e)}")
        return jsonify({'message': f'Error deleting message: {str(e)}'}), 500

# WebSocket Events

@socketio.on('connect')
def handle_connect(auth):
    """Handle client connection"""
    try:
        token = auth.get('token') if auth else None
        
        if not token:
            logger.warning("Connection attempt without token")
            return False  # Reject connection
        
        user = verify_socket_token(token)
        if not user:
            logger.warning("Connection attempt with invalid token")
            return False  # Reject connection
        
        # Store user info in session
        session['user_id'] = user.id
        session['username'] = user.username
        session['sid'] = request.sid
        
        # Add to active users
        active_users[user.username] = {
            'user_id': user.id,
            'sid': request.sid,
            'connected_at': datetime.datetime.utcnow()
        }
        
        # Join global chat room
        join_room('global_chat')
        
        # Send recent messages to the newly connected user
        try:
            recent_messages = ChatMessage.get_recent_messages(20)
            emit('recent_messages', {
                'messages': [message.to_dict() for message in recent_messages]
            })
        except Exception as e:
            logger.error(f"Error sending recent messages: {str(e)}")
        
        # Send current online users list
        emit('online_users', {
            'users': list(active_users.keys()),
            'count': len(active_users)
        })
        
        # Notify others that user joined
        emit('user_joined', {
            'username': user.username,
            'message': f'{user.username} joined the chat',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'online_count': len(active_users)
        }, room='global_chat', include_self=False)
        
        logger.info(f'User {user.username} connected (SID: {request.sid})')
        
    except Exception as e:
        logger.error(f"Connection error: {str(e)}")
        return False

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    try:
        username = session.get('username', 'Unknown')
        user_id = session.get('user_id')
        
        # Remove from active users
        if username in active_users:
            del active_users[username]
        
        # Leave global chat room
        leave_room('global_chat')
        
        # Notify others that user left
        emit('user_left', {
            'username': username,
            'message': f'{username} left the chat',
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'online_count': len(active_users)
        }, room='global_chat')
        
        # Update online users list for remaining users
        emit('online_users', {
            'users': list(active_users.keys()),
            'count': len(active_users)
        }, room='global_chat')
        
        logger.info(f'User {username} disconnected')
        
    except Exception as e:
        logger.error(f"Disconnection error: {str(e)}")

@socketio.on('send_message')
def handle_message(data):
    """Handle incoming chat messages"""
    try:
        user_id = session.get('user_id')
        username = session.get('username')
        
        if not user_id or not username:
            emit('error', {'message': 'Authentication required'})
            logger.warning("Message attempt without authentication")
            return
        
        message_content = data.get('message', '').strip()
        
        if not message_content:
            emit('error', {'message': 'Message cannot be empty'})
            return
        
        if len(message_content) > 500:
            emit('error', {'message': 'Message too long (max 500 characters)'})
            return
        
        # Save message to database
        chat_message = ChatMessage.create_message(
            user_id=user_id,
            content=message_content
        )
        
        # Prepare message data
        message_data = {
            'id': chat_message.id,
            'username': username,
            'content': message_content,
            'timestamp': chat_message.created_at.isoformat(),
            'user_id': user_id
        }
        
        # Broadcast message to all clients in global chat
        emit('receive_message', message_data, room='global_chat')
        
        logger.info(f'Message from {username}: {message_content[:50]}{"..." if len(message_content) > 50 else ""}')
        
    except ValueError as e:
        emit('error', {'message': str(e)})
        logger.warning(f"Message validation error: {str(e)}")
    except Exception as e:
        logger.error(f'Error handling message: {str(e)}')
        emit('error', {'message': 'Failed to send message'})

@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicators"""
    try:
        username = session.get('username')
        if username:
            emit('user_typing', {
                'username': username,
                'typing': data.get('typing', False)
            }, room='global_chat', include_self=False)
    except Exception as e:
        logger.error(f"Typing indicator error: {str(e)}")

@socketio.on('request_online_users')
def handle_online_users_request():
    """Handle request for online users list"""
    try:
        emit('online_users', {
            'users': list(active_users.keys()),
            'count': len(active_users)
        })
    except Exception as e:
        logger.error(f"Online users request error: {str(e)}")

@socketio.on('ping')
def handle_ping():
    """Handle ping for connection keepalive"""
    emit('pong')

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'message': 'Internal server error'}), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'message': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'message': 'Unauthorized'}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'message': 'Forbidden'}), 403

# Admin routes (optional)
@app.route('/api/admin/stats', methods=['GET'])
@token_required
def get_stats(current_user):
    """Get chat statistics (implement admin check if needed)"""
    try:
        total_users = User.query.count()
        active_users_count = User.query.filter_by(is_active=True).count()
        total_messages = ChatMessage.get_total_message_count()
        online_users_count = len(active_users)
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users_count,
            'total_messages': total_messages,
            'online_users': online_users_count,
            'online_usernames': list(active_users.keys())
        }), 200
        
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({'message': f'Error fetching stats: {str(e)}'}), 500

if __name__ == "__main__":
    # Create database tables
    with app.app_context():
        db.create_all()
        logger.info("Database tables created")
    
    # Run with SocketIO support
    logger.info("Starting chat server...")
    socketio.run(app, debug=False, host='0.0.0.0', port=1488)