#!/usr/bin/env python3
import os
import sqlite3
import uuid
import secrets
import time
import threading
import schedule
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify, abort

# Configuration
DATABASE = 'database.db'
UPLOAD_FOLDER = 'static/uploads/profile_pictures'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Contexto global para todas las plantillas
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# Template filters
@app.template_filter('time_ago')
def time_ago_filter(dt):
    """
    Formatea un objeto datetime a un string relativo como "hace 2 minutos" o "hace 5 horas".
    """
    if not dt:
        return ""
    
    try:
        # Si dt es un string, convertirlo a datetime
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        
        now = datetime.now()
        diff = now - dt
        
        # Convertir a segundos totales
        seconds = diff.total_seconds()
        
        # Definir intervalos de tiempo
        minute = 60
        hour = minute * 60
        day = hour * 24
        week = day * 7
        month = day * 30
        year = day * 365
        
        if seconds < 0:
            return "ahora mismo"
        elif seconds < minute:
            return "ahora mismo"
        elif seconds < hour:
            minutes = int(seconds / minute)
            return f"hace {minutes} {'minuto' if minutes == 1 else 'minutos'}"
        elif seconds < day:
            hours = int(seconds / hour)
            return f"hace {hours} {'hora' if hours == 1 else 'horas'}"
        elif seconds < week:
            days = int(seconds / day)
            return f"hace {days} {'día' if days == 1 else 'días'}"
        elif seconds < month:
            weeks = int(seconds / week)
            return f"hace {weeks} {'semana' if weeks == 1 else 'semanas'}"
        elif seconds < year:
            months = int(seconds / month)
            return f"hace {months} {'mes' if months == 1 else 'meses'}"
        else:
            years = int(seconds / year)
            return f"hace {years} {'año' if years == 1 else 'años'}"
    except Exception as e:
        app.logger.error(f"Error en time_ago_filter: {e}")
        return str(dt)

@app.template_filter('date_format')
def date_format_filter(dt):
    """
    Formatea un objeto datetime a un formato de fecha legible.
    """
    if not dt:
        return ""
    
    try:
        # Si dt es un string, convertirlo a datetime
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            
        return dt.strftime("%d %b, %Y")
    except Exception as e:
        app.logger.error(f"Error en date_format_filter: {e}")
        return str(dt)

# Database functions
def get_db():
    """Connect to the database and return a connection object."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Return rows as dictionaries
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Close the database connection when the app context ends."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database with required tables."""
    with app.app_context():
        db = get_db()
        
        # Create users table
        db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            profile_picture_path TEXT,
            bio TEXT,
            invitation_link TEXT UNIQUE NOT NULL,
            paranoia_mode_enabled BOOLEAN DEFAULT 0,
            paranoia_mode_duration INTEGER DEFAULT 30,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create messages table
        db.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message_text TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT 0,
            paranoia_mode_enabled BOOLEAN NOT NULL,
            destruction_time TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (user_id),
            FOREIGN KEY (receiver_id) REFERENCES users (user_id)
        )
        ''')
        
        # Create contacts table
        db.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            contact_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id),
            FOREIGN KEY (friend_user_id) REFERENCES users (user_id),
            UNIQUE (user_id, friend_user_id)
        )
        ''')
        
        # Create chat_sessions table to track active chats
        db.execute('''
        CREATE TABLE IF NOT EXISTS chat_sessions (
            session_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id INTEGER NOT NULL,
            user2_id INTEGER NOT NULL,
            last_message_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user1_id) REFERENCES users (user_id),
            FOREIGN KEY (user2_id) REFERENCES users (user_id),
            UNIQUE (user1_id, user2_id)
        )
        ''')
        
        # Create user_activity table to track online status
        db.execute('''
        CREATE TABLE IF NOT EXISTS user_activity (
            user_id INTEGER PRIMARY KEY,
            last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_online BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
        ''')
        
        db.commit()

# Helper functions
def allowed_file(filename):
    """Check if a file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_invitation_link():
    """Generate a unique invitation link for a new user."""
    return f"cipher-cup-invite-{uuid.uuid4().hex[:12]}"

def login_required(f):
    """Decorator to require login for certain routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Inicio de sesión requerido para acceder a esta página.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def update_user_activity():
    """Update the user's last active timestamp."""
    if 'user_id' in session:
        db = get_db()
        user_id = session['user_id']
        
        # Check if record exists
        exists = db.execute('SELECT 1 FROM user_activity WHERE user_id = ?', 
                           (user_id,)).fetchone()
        
        if exists:
            db.execute('UPDATE user_activity SET last_active = CURRENT_TIMESTAMP, is_online = 1 WHERE user_id = ?', 
                      (user_id,))
        else:
            db.execute('INSERT INTO user_activity (user_id, is_online) VALUES (?, 1)', 
                      (user_id,))
        
        db.commit()

# Schedule function to delete expired messages
def check_and_delete_expired_messages():
    """Check for and delete messages that have expired based on paranoia mode."""
    app.logger.info("Checking for expired messages...")
    with app.app_context():
        db = get_db()
        current_time = datetime.now()
        
        # Find expired messages
        expired_messages = db.execute('''
            SELECT message_id FROM messages 
            WHERE paranoia_mode_enabled = 1 
            AND destruction_time IS NOT NULL 
            AND destruction_time <= ?
        ''', (current_time,)).fetchall()
        
        if expired_messages:
            # Delete expired messages
            for message in expired_messages:
                db.execute('DELETE FROM messages WHERE message_id = ?', (message['message_id'],))
            
            db.commit()
            app.logger.info(f"Deleted {len(expired_messages)} expired messages.")

# Start a background thread for message cleanup
def start_message_cleanup_scheduler():
    """Start the scheduler for message cleanup."""
    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(1)
    
    # Schedule the cleanup job to run every 5 seconds
    schedule.every(5).seconds.do(check_and_delete_expired_messages)
    
    # Start the scheduler in a daemon thread
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()

# Route handlers
@app.before_request
def before_request():
    """Actions to perform before each request."""
    update_user_activity()

@app.route('/')
def index():
    """Home page - redirects to login if not authenticated, otherwise shows main chat UI."""
    if 'user_id' in session:
        return render_template('index.html')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page and handler."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        bio = request.form.get('bio', '')
        
        # Validate form data
        if not username or not password:
            flash('Nombre de usuario y contraseña son requeridos.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Las contraseñas no coinciden.', 'error')
            return render_template('register.html')
        
        # Check if username already exists
        db = get_db()
        existing_user = db.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            flash('Nombre de usuario ya existe. Por favor elige otro.', 'error')
            return render_template('register.html')
        
        # Handle profile picture upload
        profile_picture_path = None
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(f"{username}_{int(time.time())}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                profile_picture_path = f"uploads/profile_pictures/{filename}"
        
        # Generate unique invitation link
        invitation_link = generate_invitation_link()
        
        # Hash password and save user
        password_hash = generate_password_hash(password)
        db.execute(
            'INSERT INTO users (username, password_hash, profile_picture_path, bio, invitation_link) VALUES (?, ?, ?, ?, ?)',
            (username, password_hash, profile_picture_path, bio, invitation_link)
        )
        db.commit()
        
        # Get the new user's ID
        user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username,)).fetchone()['user_id']
        
        # Log the user in
        session['user_id'] = user_id
        session['username'] = username
        session.permanent = True
        
        flash('¡Registro exitoso! Bienvenido a CipherCup.', 'success')
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page and handler."""
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Por favor proporciona nombre de usuario y contraseña.', 'error')
            return render_template('login.html')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session.permanent = True
            
            # Update user activity
            db.execute(
                'INSERT OR REPLACE INTO user_activity (user_id, last_active, is_online) VALUES (?, CURRENT_TIMESTAMP, 1)',
                (user['user_id'],)
            )
            db.commit()
            
            return redirect(url_for('index'))
        else:
            flash('Credenciales inválidas. Por favor intenta de nuevo.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Log the user out and redirect to login page."""
    if 'user_id' in session:
        db = get_db()
        db.execute('UPDATE user_activity SET is_online = 0 WHERE user_id = ?', (session['user_id'],))
        db.commit()
    
    session.clear()
    flash('Has cerrado sesión exitosamente.', 'success')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    """Display the user's profile."""
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE user_id = ?', (session['user_id'],)).fetchone()
    
    if not user:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('index'))
    
    return render_template('profile.html', user=user)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    """Update the user's profile information."""
    db = get_db()
    user_id = session['user_id']
    
    username = request.form.get('username')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    bio = request.form.get('bio', '')
    
    # Get current user info
    user = db.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
    if not user:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('profile'))
    
    # Update username if changed
    if username and username != user['username']:
        # Check if new username is already taken
        existing = db.execute('SELECT 1 FROM users WHERE username = ? AND user_id != ?', 
                             (username, user_id)).fetchone()
        if existing:
            flash('Nombre de usuario ya existe. Por favor elige otro.', 'error')
            return redirect(url_for('profile'))
        
        db.execute('UPDATE users SET username = ? WHERE user_id = ?', (username, user_id))
        session['username'] = username
    
    # Update password if requested
    if current_password and new_password:
        if not check_password_hash(user['password_hash'], current_password):
            flash('Contraseña actual incorrecta.', 'error')
            return redirect(url_for('profile'))
        
        if new_password != confirm_password:
            flash('Las nuevas contraseñas no coinciden.', 'error')
            return redirect(url_for('profile'))
        
        password_hash = generate_password_hash(new_password)
        db.execute('UPDATE users SET password_hash = ? WHERE user_id = ?', (password_hash, user_id))
        flash('Contraseña actualizada exitosamente.', 'success')
    
    # Update bio
    db.execute('UPDATE users SET bio = ? WHERE user_id = ?', (bio, user_id))
    
    # Handle profile picture update
    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and file.filename and allowed_file(file.filename):
            # Delete old profile picture if exists
            if user['profile_picture_path']:
                old_path = os.path.join('static', user['profile_picture_path'])
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            filename = secure_filename(f"{username}_{int(time.time())}_{file.filename}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            profile_picture_path = f"uploads/profile_pictures/{filename}"
            
            db.execute('UPDATE users SET profile_picture_path = ? WHERE user_id = ?', 
                      (profile_picture_path, user_id))
    
    db.commit()
    flash('Perfil actualizado exitosamente.', 'success')
    return redirect(url_for('profile'))

@app.route('/profile/paranoia', methods=['POST'])
@login_required
def update_paranoia_settings():
    """Update the user's paranoia mode settings."""
    db = get_db()
    user_id = session['user_id']
    
    enabled = request.form.get('paranoia_mode_enabled', '0') == '1'
    duration = request.form.get('paranoia_mode_duration', '30')
    
    # Validate duration
    try:
        duration = int(duration)
        if duration < 5:
            duration = 5  # Minimum 5 seconds
        elif duration > 86400:
            duration = 86400  # Maximum 24 hours
    except ValueError:
        duration = 30  # Default to 30 seconds if invalid
    
    db.execute(
        'UPDATE users SET paranoia_mode_enabled = ?, paranoia_mode_duration = ? WHERE user_id = ?',
        (enabled, duration, user_id)
    )
    db.commit()
    
    flash('Configuración de modo paranoia actualizada.', 'success')
    return redirect(url_for('profile'))

@app.route('/invitation/<link>')
def process_invitation(link):
    """Process an invitation link."""
    if 'user_id' not in session:
        # Store the invitation link in session for after login
        session['pending_invitation'] = link
        flash('Por favor inicia sesión o regístrate para aceptar esta invitación.', 'info')
        return redirect(url_for('login'))
    
    db = get_db()
    inviter = db.execute('SELECT user_id, username FROM users WHERE invitation_link = ?', (link,)).fetchone()
    
    if not inviter:
        flash('Enlace de invitación inválido.', 'error')
        return redirect(url_for('index'))
    
    # Don't allow adding yourself
    if inviter['user_id'] == session['user_id']:
        flash('No puedes agregarte a ti mismo como contacto.', 'error')
        return redirect(url_for('contacts'))
    
    # Check if already a contact
    existing = db.execute(
        'SELECT 1 FROM contacts WHERE user_id = ? AND friend_user_id = ?', 
        (session['user_id'], inviter['user_id'])
    ).fetchone()
    
    if existing:
        flash(f'{inviter["username"]} ya está en tu lista de contactos.', 'info')
        return redirect(url_for('contacts'))
    
    # Add contact (bidirectional)
    try:
        # Add inviter to user's contacts
        db.execute(
            'INSERT INTO contacts (user_id, friend_user_id) VALUES (?, ?)',
            (session['user_id'], inviter['user_id'])
        )
        
        # Add user to inviter's contacts
        db.execute(
            'INSERT INTO contacts (user_id, friend_user_id) VALUES (?, ?)',
            (inviter['user_id'], session['user_id'])
        )
        
        db.commit()
        flash(f'Has agregado a {inviter["username"]} a tus contactos.', 'success')
    except sqlite3.IntegrityError:
        db.rollback()
        flash('Error al agregar contacto. Intenta de nuevo.', 'error')
    
    return redirect(url_for('contacts'))

@app.route('/contacts')
@login_required
def contacts():
    """Display the user's contacts."""
    db = get_db()
    user_id = session['user_id']
    
    # Get user's contacts with online status
    contacts = db.execute('''
        SELECT u.user_id, u.username, u.profile_picture_path, u.bio, 
               CASE WHEN a.is_online = 1 THEN 1 ELSE 0 END as is_online
        FROM contacts c
        JOIN users u ON c.friend_user_id = u.user_id
        LEFT JOIN user_activity a ON u.user_id = a.user_id
        WHERE c.user_id = ?
        ORDER BY is_online DESC, u.username
    ''', (user_id,)).fetchall()
    
    # Get user's invitation link
    invitation_link = db.execute(
        'SELECT invitation_link FROM users WHERE user_id = ?', 
        (user_id,)
    ).fetchone()['invitation_link']
    
    full_invitation_url = f"{request.host_url}invitation/{invitation_link}"
    
    return render_template('contacts.html', contacts=contacts, invitation_url=full_invitation_url)

@app.route('/contacts/remove/<int:friend_id>', methods=['POST'])
@login_required
def remove_contact(friend_id):
    """Remove a contact from the user's list."""
    db = get_db()
    user_id = session['user_id']
    
    # Remove bidirectional contacts
    db.execute('DELETE FROM contacts WHERE user_id = ? AND friend_user_id = ?', 
              (user_id, friend_id))
    db.execute('DELETE FROM contacts WHERE user_id = ? AND friend_user_id = ?', 
              (friend_id, user_id))
    
    # Also remove from chat sessions
    db.execute('''
        DELETE FROM chat_sessions 
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
    ''', (user_id, friend_id, friend_id, user_id))
    
    db.commit()
    
    flash('Contacto eliminado exitosamente.', 'success')
    return redirect(url_for('contacts'))

@app.route('/chats')
@login_required
def chats():
    """Show list of user's active chats."""
    db = get_db()
    user_id = session['user_id']
    
    # Get list of chats with latest message and unread count
    chats = db.execute('''
        WITH chat_partners AS (
            SELECT user2_id AS partner_id FROM chat_sessions WHERE user1_id = ?
            UNION
            SELECT user1_id AS partner_id FROM chat_sessions WHERE user2_id = ?
        ),
        latest_messages AS (
            SELECT 
                cp.partner_id,
                m.message_text,
                m.timestamp,
                (SELECT COUNT(*) FROM messages 
                 WHERE sender_id = cp.partner_id AND receiver_id = ? AND is_read = 0) AS unread_count
            FROM chat_partners cp
            LEFT JOIN messages m ON (m.sender_id = cp.partner_id AND m.receiver_id = ?) 
                                 OR (m.sender_id = ? AND m.receiver_id = cp.partner_id)
            WHERE m.timestamp = (
                SELECT MAX(timestamp) FROM messages 
                WHERE (sender_id = cp.partner_id AND receiver_id = ?) 
                   OR (sender_id = ? AND receiver_id = cp.partner_id)
            )
        )
        SELECT 
            u.user_id, 
            u.username, 
            u.profile_picture_path,
            lm.message_text AS last_message,
            lm.timestamp AS last_message_time,
            lm.unread_count,
            CASE WHEN ua.is_online = 1 THEN 1 ELSE 0 END as is_online
        FROM latest_messages lm
        JOIN users u ON lm.partner_id = u.user_id
        LEFT JOIN user_activity ua ON u.user_id = ua.user_id
        ORDER BY lm.timestamp DESC
    ''', (user_id, user_id, user_id, user_id, user_id, user_id, user_id)).fetchall()
    
    return render_template('chats.html', chats=chats)

@app.route('/chat/<int:partner_id>')
@login_required
def chat_view(partner_id):
    """Show chat with a specific user."""
    db = get_db()
    user_id = session['user_id']
    
    # Verify partner is a contact
    is_contact = db.execute(
        'SELECT 1 FROM contacts WHERE user_id = ? AND friend_user_id = ?', 
        (user_id, partner_id)
    ).fetchone()
    
    if not is_contact:
        flash('Este usuario no está en tu lista de contactos.', 'error')
        return redirect(url_for('contacts'))
    
    # Get partner info
    partner = db.execute('SELECT * FROM users WHERE user_id = ?', (partner_id,)).fetchone()
    if not partner:
        flash('Usuario no encontrado.', 'error')
        return redirect(url_for('contacts'))
    
    # Create or update chat session
    existing_session = db.execute('''
        SELECT session_id FROM chat_sessions 
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
    ''', (user_id, partner_id, partner_id, user_id)).fetchone()
    
    if existing_session:
        db.execute('UPDATE chat_sessions SET last_message_time = CURRENT_TIMESTAMP WHERE session_id = ?', 
                  (existing_session['session_id'],))
    else:
        db.execute(
            'INSERT INTO chat_sessions (user1_id, user2_id) VALUES (?, ?)',
            (user_id, partner_id)
        )
    
    # Mark messages as read
    db.execute(
        'UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0',
        (partner_id, user_id)
    )
    
    db.commit()
    
    # Get messages
    messages = db.execute('''
        SELECT 
            m.message_id, 
            m.sender_id, 
            m.message_text, 
            m.timestamp,
            m.paranoia_mode_enabled,
            m.destruction_time,
            u.username as sender_name
        FROM messages m
        JOIN users u ON m.sender_id = u.user_id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.timestamp
    ''', (user_id, partner_id, partner_id, user_id)).fetchall()
    
    return render_template('chat.html', partner=partner, messages=messages)

@app.route('/chat/<int:partner_id>/send', methods=['POST'])
@login_required
def send_message(partner_id):
    """Send a message to a specific user."""
    db = get_db()
    user_id = session['user_id']
    message_text = request.form.get('message')
    
    if not message_text:
        return jsonify({'error': 'Mensaje vacío'}), 400
    
    # Verify partner is a contact
    is_contact = db.execute(
        'SELECT 1 FROM contacts WHERE user_id = ? AND friend_user_id = ?', 
        (user_id, partner_id)
    ).fetchone()
    
    if not is_contact:
        return jsonify({'error': 'Este usuario no está en tu lista de contactos'}), 403
    
    # Get user's paranoia mode settings
    user = db.execute(
        'SELECT paranoia_mode_enabled, paranoia_mode_duration FROM users WHERE user_id = ?', 
        (user_id,)
    ).fetchone()
    
    paranoia_enabled = user['paranoia_mode_enabled']
    destruction_time = None
    
    if paranoia_enabled:
        # Calculate destruction time
        now = datetime.now()
        delta = timedelta(seconds=user['paranoia_mode_duration'])
        destruction_time = now + delta
    
    # Insert message
    cursor = db.execute(
        '''INSERT INTO messages 
           (sender_id, receiver_id, message_text, paranoia_mode_enabled, destruction_time) 
           VALUES (?, ?, ?, ?, ?)''',
        (user_id, partner_id, message_text, paranoia_enabled, destruction_time)
    )
    message_id = cursor.lastrowid
    
    # Update chat session
    existing_session = db.execute('''
        SELECT session_id FROM chat_sessions 
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
    ''', (user_id, partner_id, partner_id, user_id)).fetchone()
    
    if existing_session:
        db.execute('UPDATE chat_sessions SET last_message_time = CURRENT_TIMESTAMP WHERE session_id = ?', 
                  (existing_session['session_id'],))
    else:
        db.execute(
            'INSERT INTO chat_sessions (user1_id, user2_id) VALUES (?, ?)',
            (user_id, partner_id)
        )
    
    db.commit()
    
    # Return success
    return jsonify({
        'success': True, 
        'message_id': message_id,
        'paranoia_enabled': paranoia_enabled,
        'destruction_time': destruction_time.isoformat() if destruction_time else None
    })

@app.route('/messages/check', methods=['GET'])
@login_required
def check_messages():
    """Check for new messages and update message status."""
    db = get_db()
    user_id = session['user_id']
    
    # Get timestamp of last message client has seen
    last_seen = request.args.get('last_seen', '1970-01-01')
    
    # Get new messages
    new_messages = db.execute('''
        SELECT 
            m.message_id, 
            m.sender_id, 
            m.receiver_id,
            m.message_text, 
            m.timestamp,
            m.paranoia_mode_enabled,
            m.destruction_time,
            u.username as sender_name
        FROM messages m
        JOIN users u ON m.sender_id = u.user_id
        WHERE m.receiver_id = ? AND m.timestamp > ?
        ORDER BY m.timestamp
    ''', (user_id, last_seen)).fetchall()
    
    # Convert new messages to dict for JSON
    messages = []
    for msg in new_messages:
        messages.append({
            'id': msg['message_id'],
            'sender_id': msg['sender_id'],
            'text': msg['message_text'],
            'timestamp': msg['timestamp'],
            'sender_name': msg['sender_name'],
            'paranoia_enabled': bool(msg['paranoia_mode_enabled']),
            'destruction_time': msg['destruction_time']
        })
    
    # Get expired messages (those that should no longer be shown)
    expired_messages = []
    if new_messages:
        expired = db.execute('''
            SELECT message_id FROM messages 
            WHERE paranoia_mode_enabled = 1 
            AND destruction_time IS NOT NULL 
            AND destruction_time <= CURRENT_TIMESTAMP
            AND (sender_id = ? OR receiver_id = ?)
        ''', (user_id, user_id)).fetchall()
        
        expired_messages = [m['message_id'] for m in expired]
    
    return jsonify({
        'messages': messages,
        'expired_messages': expired_messages
    })

@app.route('/api/search-users', methods=['GET'])
@login_required
def search_users():
    """Search for users by username."""
    query = request.args.get('q', '')
    if len(query) < 3:
        return jsonify([])
    
    db = get_db()
    user_id = session['user_id']
    
    # Search for users not already in contacts
    users = db.execute('''
        SELECT user_id, username, profile_picture_path
        FROM users
        WHERE username LIKE ? 
        AND user_id != ?
        AND user_id NOT IN (SELECT friend_user_id FROM contacts WHERE user_id = ?)
        LIMIT 10
    ''', (f'%{query}%', user_id, user_id)).fetchall()
    
    # Convert to list of dicts for JSON
    results = []
    for user in users:
        results.append({
            'id': user['user_id'],
            'username': user['username'],
            'profile_picture': user['profile_picture_path']
        })
    
    return jsonify(results)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

# Initialize app
if __name__ == '__main__':
    # Ensure DB is created
    init_db()
    
    # Start background thread for message cleanup
    start_message_cleanup_scheduler()
    
    # Run the app
    app.run(debug=True, host='0.0.0.0')