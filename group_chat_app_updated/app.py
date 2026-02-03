from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message as MailMessage
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-12345')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///groupchat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['ADMIN_CREATION_CODE'] = os.environ.get('ADMIN_CREATION_CODE', 'letmein123')

FIXED_ROOM_ID = 'Room7013'

app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'webm'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'localhost')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 1025))
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@groupchat.com')

db = SQLAlchemy(app)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading', ping_timeout=60, ping_interval=25)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ==========================================
# DATABASE MODELS
# ==========================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(50), unique=True, nullable=False)
    room_name = db.Column(db.String(100), nullable=False)
    created_by = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    def to_dict(self):
        return {
            'id': self.id, 'room_id': self.room_id, 'room_name': self.room_name,
            'created_by': self.created_by, 'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    message = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), default='text')
    file_url = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    def to_dict(self):
        return {
            'id': self.id, 'room_id': self.room_id, 'username': self.username,
            'message': self.message, 'message_type': self.message_type,
            'file_url': self.file_url,
            'timestamp': self.timestamp.strftime('%I:%M %p'),
            'date': self.timestamp.strftime('%Y-%m-%d')
        }

class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=True)

active_users = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_defaults():
    if not User.query.filter_by(email='admin@example.com').first():
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('admin123')
        db.session.add(admin)
        print('✓ Default admin created')
    if not Room.query.filter_by(room_id=FIXED_ROOM_ID).first():
        fixed_room = Room(room_id=FIXED_ROOM_ID, room_name='Global Group Chat', created_by='system')
        db.session.add(fixed_room)
        print(f'✓ Fixed room created: {FIXED_ROOM_ID}')
    db.session.commit()

with app.app_context():
    db.create_all()
    create_defaults()

# ==========================================
# AUTHENTICATION ROUTES
# ==========================================

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('join_room_page'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('join_room_page'))
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        if not email or not password:
            error = 'Please provide both email and password'
        else:
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                login_user(user, remember=bool(remember))
                flash(f'Welcome back, {user.username}!', 'success')
                next_page = request.args.get('next')
                if user.role == 'admin':
                    return redirect(next_page or url_for('admin_dashboard'))
                return redirect(next_page or url_for('join_room_page'))
            else:
                error = 'Invalid email or password'
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('join_room_page'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        if not all([username, email, password, confirm_password]):
            error = 'All fields are required'
        elif password != confirm_password:
            error = 'Passwords do not match'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters'
        elif User.query.filter_by(email=email).first():
            error = 'Email already registered'
        elif User.query.filter_by(username=username).first():
            error = 'Username already taken'
        else:
            new_user = User(username=username, email=email, role='user')
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    error = None
    success = False
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            error = 'Please provide your email'
        else:
            user = User.query.filter_by(email=email).first()
            if user:
                token = serializer.dumps(user.email, salt='password-reset-salt')
                reset_url = url_for('reset_with_token', token=token, _external=True)
                msg = MailMessage('Password Reset Request', recipients=[user.email])
                msg.body = f'Click the link to reset your password: {reset_url}\n\nValid for 1 hour.'
                try:
                    mail.send(msg)
                    success = True
                except Exception as e:
                    print(f'Mail error: {e}')
                    print(f'Reset link: {reset_url}')
                    flash('Mail not configured. Check console for reset link.', 'warning')
                    success = True
            else:
                error = 'No account found with that email'
    return render_template('forgot.html', error=error, success=success)

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash('Invalid or expired reset link', 'danger')
        return redirect(url_for('forgot'))
    user = User.query.filter_by(email=email).first_or_404()
    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        if not password or not confirm_password:
            error = 'All fields are required'
        elif password != confirm_password:
            error = 'Passwords do not match'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters'
        else:
            user.set_password(password)
            db.session.commit()
            flash('Password updated successfully! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', error=error)

# ==========================================
# ROOM & CHAT ROUTES
# ==========================================

@app.route('/join-room', methods=['GET', 'POST'])
@login_required
def join_room_page():
    error = None
    if request.method == 'POST':
        room_id = request.form.get('room_id', '').strip()
        if not room_id:
            error = 'Please enter the Room ID'
        elif room_id != FIXED_ROOM_ID:
            error = f'Invalid Room ID'
        else:
            return redirect(url_for('chat_room', room_id=FIXED_ROOM_ID))
    show_room_id = (current_user.role == 'admin')
    return render_template('join_room.html', error=error, show_room_id=show_room_id, fixed_room_id=FIXED_ROOM_ID)

@app.route('/room/<room_id>')
@login_required
def chat_room(room_id):
    if room_id != FIXED_ROOM_ID:
        flash('Invalid Room ID', 'danger')
        return redirect(url_for('join_room_page'))
    room = Room.query.filter_by(room_id=room_id).first()
    if not room or not room.is_active:
        flash('Room not found or inactive', 'danger')
        return redirect(url_for('join_room_page'))
    existing_member = RoomMember.query.filter_by(room_id=room_id, username=current_user.username).first()
    if not existing_member:
        new_member = RoomMember(room_id=room_id, username=current_user.username, is_online=True)
        db.session.add(new_member)
        db.session.commit()
    show_room_id = (current_user.role == 'admin')
    return render_template('chat.html', room=room, username=current_user.username, room_id=room_id, show_room_id=show_room_id)

@app.route('/api/room/<room_id>/messages')
@login_required
def get_room_messages(room_id):
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).limit(200).all()
    return jsonify({'messages': [msg.to_dict() for msg in messages], 'count': len(messages)})

@app.route('/api/room/<room_id>/members')
@login_required
def get_room_members(room_id):
    members = RoomMember.query.filter_by(room_id=room_id).all()
    online_members = [u['username'] for u in active_users.values() if u['room_id'] == room_id]
    return jsonify({
        'all_members': [{'username': m.username, 'joined_at': m.joined_at.strftime('%Y-%m-%d')} for m in members],
        'online_members': list(set(online_members)),
        'online_count': len(set(online_members)),
        'total_count': len(members)
    })

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    
    # Handle empty filename or blob files from camera
    if file.filename == '' or file.filename == 'blob':
        file.filename = f'camera_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.jpg'
    
    # Check if file is allowed
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    
    filename = secure_filename(file.filename)
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    name, ext = os.path.splitext(filename)
    
    # Ensure extension exists (for camera blobs)
    if not ext:
        ext = '.jpg'
    
    unique_filename = f"{name}_{timestamp}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    try:
        file.save(filepath)
    except Exception as e:
        return jsonify({'error': f'Failed to save file: {str(e)}'}), 500
    
    file_url = f'/static/uploads/{unique_filename}'
    file_type = 'image' if ext.lower() in ['.png', '.jpg', '.jpeg', '.gif'] else 'video'
    
    return jsonify({
        'success': True,
        'file_url': file_url,
        'file_type': file_type,
        'filename': unique_filename
    })

# ==========================================
# ADMIN ROUTES
# ==========================================

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('join_room_page'))
    total_users = User.query.count()
    total_rooms = Room.query.count()
    total_messages = Message.query.count()
    active_rooms = Room.query.filter_by(is_active=True).all()
    return render_template('admin_dashboard.html', total_users=total_users, total_rooms=total_rooms,
                         total_messages=total_messages, rooms=active_rooms, fixed_room_id=FIXED_ROOM_ID)

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('join_room_page'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/add-user', methods=['POST'])
@login_required
def admin_add_user():
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')
    if not all([username, email, password]) or len(password) < 6:
        flash('Invalid input', 'danger')
        return redirect(url_for('admin_users'))
    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        flash('User already exists', 'danger')
        return redirect(url_for('admin_users'))
    new_user = User(username=username, email=email, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash(f'User {username} added!', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/edit-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('join_room_page'))
    user = User.query.get_or_404(user_id)
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'user')
        if not username or not email:
            error = 'Username and email are required'
        else:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user and existing_user.id != user_id:
                error = 'Username already taken'
            existing_email = User.query.filter_by(email=email).first()
            if existing_email and existing_email.id != user_id:
                error = 'Email already registered'
            if password and len(password) < 6:
                error = 'Password must be at least 6 characters'
        if not error:
            user.username = username
            user.email = email
            user.role = role
            if password:
                user.set_password(password)
            db.session.commit()
            flash(f'User {username} updated!', 'success')
            return redirect(url_for('admin_users'))
    return render_template('admin_edit_user.html', user=user, error=error)

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    user = User.query.get_or_404(user_id)
    if user.email == 'admin@example.com':
        flash('Cannot delete default admin', 'warning')
        return redirect(url_for('admin_users'))
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted', 'info')
    return redirect(url_for('admin_users'))

@app.route('/admin/messages')
@login_required
def admin_messages():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('join_room_page'))
    room_filter = request.args.get('room', None)
    user_filter = request.args.get('user', None)
    query = Message.query
    if room_filter:
        query = query.filter_by(room_id=room_filter)
    if user_filter:
        query = query.filter_by(username=user_filter)
    messages = query.order_by(Message.timestamp.desc()).limit(500).all()
    rooms = Room.query.filter_by(is_active=True).all()
    users = User.query.all()
    return render_template('admin_messages.html', messages=messages, rooms=rooms, users=users,
                         room_filter=room_filter, user_filter=user_filter)

@app.route('/admin/edit-message/<int:message_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_message(message_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('join_room_page'))
    message = Message.query.get_or_404(message_id)
    error = None
    if request.method == 'POST':
        new_message_text = request.form.get('message', '').strip()
        if not new_message_text:
            error = 'Message text is required'
        else:
            message.message = new_message_text
            db.session.commit()
            socketio.emit('message_edited', {
                'message_id': message.id,
                'new_text': new_message_text,
                'edited_by': 'Admin'
            }, room=message.room_id)
            flash(f'Message updated successfully!', 'success')
            return redirect(url_for('admin_messages'))
    return render_template('admin_edit_message.html', message=message, error=error)

@app.route('/admin/delete-message/<int:message_id>', methods=['POST'])
@login_required
def admin_delete_message(message_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    message = Message.query.get_or_404(message_id)
    room_id = message.room_id
    if message.file_url:
        file_path = os.path.join('static', message.file_url.lstrip('/static/'))
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f'Error deleting file: {e}')
    db.session.delete(message)
    db.session.commit()
    socketio.emit('message_deleted', {'message_id': message_id}, room=room_id)
    flash('Message deleted successfully', 'info')
    return redirect(url_for('admin_messages'))

# ==========================================
# SOCKETIO EVENTS
# ==========================================

@socketio.on('connect')
def handle_connect():
    print(f'[CONNECT] {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in active_users:
        user_data = active_users[request.sid]
        username = user_data['username']
        room_id = user_data['room_id']
        del active_users[request.sid]
        member = RoomMember.query.filter_by(room_id=room_id, username=username).first()
        if member:
            member.is_online = False
            db.session.commit()
        online_members = list(set([u['username'] for u in active_users.values() if u['room_id'] == room_id]))
        socketio.emit('user_left', {'username': username, 'online_members': online_members, 'message': f'{username} left'}, room=room_id)
        print(f'[DISCONNECT] {username}')

@socketio.on('join_room')
def handle_join_room(data):
    room_id = data.get('room_id')
    username = data.get('username')
    if not room_id or not username:
        emit('error', {'message': 'Invalid'})
        return
    room = Room.query.filter_by(room_id=room_id).first()
    if not room:
        emit('error', {'message': 'Room not found'})
        return
    join_room(room_id)
    active_users[request.sid] = {'username': username, 'room_id': room_id}
    member = RoomMember.query.filter_by(room_id=room_id, username=username).first()
    if member:
        member.is_online = True
        db.session.commit()
    online_members = list(set([u['username'] for u in active_users.values() if u['room_id'] == room_id]))
    socketio.emit('user_joined', {'username': username, 'online_members': online_members, 'message': f'{username} joined'}, room=room_id)
    print(f'[JOIN] {username}')

@socketio.on('leave_room')
def handle_leave_room(data):
    room_id = data.get('room_id')
    username = data.get('username')
    leave_room(room_id)
    if request.sid in active_users:
        del active_users[request.sid]
    member = RoomMember.query.filter_by(room_id=room_id, username=username).first()
    if member:
        member.is_online = False
        db.session.commit()
    online_members = list(set([u['username'] for u in active_users.values() if u['room_id'] == room_id]))
    socketio.emit('user_left', {'username': username, 'online_members': online_members, 'message': f'{username} left'}, room=room_id)

@socketio.on('send_message')
def handle_send_message(data):
    room_id = data.get('room_id')
    username = data.get('username')
    message_text = data.get('message', '').strip()
    message_type = data.get('message_type', 'text')
    file_url = data.get('file_url', None)
    if not message_text and not file_url:
        return
    new_message = Message(
        room_id=room_id,
        username=username,
        message=message_text if message_text else '',
        message_type=message_type,
        file_url=file_url,
        timestamp=datetime.utcnow()
    )
    db.session.add(new_message)
    db.session.commit()
    message_data = {
        'id': new_message.id,
        'username': username,
        'message': message_text if message_text else '',
        'message_type': message_type,
        'file_url': file_url,
        'timestamp': new_message.timestamp.strftime('%I:%M %p'),
        'date': new_message.timestamp.strftime('%Y-%m-%d')
    }
    socketio.emit('receive_message', message_data, room=room_id, include_self=True)
    print(f'[MESSAGE] {username}: {message_text if message_text else f"[{message_type}]"}')

@socketio.on('typing')
def handle_typing(data):
    room_id = data.get('room_id')
    username = data.get('username')
    is_typing = data.get('is_typing', False)
    socketio.emit('user_typing', {'username': username, 'is_typing': is_typing}, room=room_id, include_self=False)

@socketio.on('edit_message')
def handle_edit_message(data):
    message_id = data.get('message_id')
    new_text = data.get('new_text', '').strip()
    username = data.get('username')
    room_id = data.get('room_id')
    if not message_id or not new_text or not username:
        emit('error', {'message': 'Invalid edit request'})
        return
    message = Message.query.get(message_id)
    if not message or message.username != username:
        emit('error', {'message': 'Cannot edit this message'})
        return
    message.message = new_text
    db.session.commit()
    socketio.emit('message_edited', {'message_id': message_id, 'new_text': new_text}, room=room_id)
    print(f'[EDIT] {username} edited message {message_id}')

@socketio.on('delete_message')
def handle_delete_message(data):
    message_id = data.get('message_id')
    username = data.get('username')
    room_id = data.get('room_id')
    if not message_id or not username:
        emit('error', {'message': 'Invalid delete request'})
        return
    message = Message.query.get(message_id)
    if not message or message.username != username:
        emit('error', {'message': 'Cannot delete this message'})
        return
    if message.file_url:
        file_path = os.path.join('static', message.file_url.lstrip('/static/'))
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f'[DELETE] Removed file: {file_path}')
            except Exception as e:
                print(f'[ERROR] Could not delete file: {e}')
    db.session.delete(message)
    db.session.commit()
    socketio.emit('message_deleted', {'message_id': message_id}, room=room_id)
    print(f'[DELETE] {username} deleted message {message_id}')

if __name__ == '__main__':
    # Enable HTTPS for camera access (optional for localhost)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
