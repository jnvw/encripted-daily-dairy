import base64
import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-123'
import os
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
CORS(app)

allowed_origins = [
    "https://dailydiary.up.railway.app",  # Your Production URL
    "http://localhost:5000",              # Your Local Machine
    "http://127.0.0.1:5000"               # Your Local Machine (IP)
]

# Enable CORS only for these origins
CORS(app, resources={
    r"/*": {"origins": allowed_origins}
})
# Get the database URL from the environment (Neon), or default to SQLite (Local)
database_url = os.environ.get('DATABASE_URL', 'sqlite:///dairy_diary.db')

# Compatibility fix: SQLAlchemy requires 'postgresql://', but Neon gives 'postgres://'
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'error' 
# This sets a cleaner, singular message
login_manager.login_message = "Please log in to access your diary."

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.LargeBinary, nullable=False) 

class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(10), nullable=False)
    content = db.Column(db.LargeBinary, nullable=False) 
    food = db.Column(db.LargeBinary, nullable=True)    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- Encryption Helper ---
def get_encryption_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
@login_required
def index():
    return render_template('index.html', current_user=current_user)

@app.route('/api/dates')
@login_required
def get_dates():
    """Returns a list of dates that have entries for the current user."""
    entries = Entry.query.filter_by(user_id=current_user.id).all()
    dates = [e.date for e in entries]
    return jsonify(dates)

@app.route('/api/get_entry/<date_str>')
@login_required
def get_entry(date_str):
    """Fetches and decrypts the entry for a specific date."""
    entry = Entry.query.filter_by(user_id=current_user.id, date=date_str).first()
    user_pass = request.cookies.get('user_pass')
    
    if not entry:
        return jsonify({"content": "", "food": ""})

    if user_pass:
        try:
            key = get_encryption_key(user_pass, current_user.salt)
            fernet = Fernet(key)
            return jsonify({
                "content": fernet.decrypt(entry.content).decode(),
                "food": fernet.decrypt(entry.food).decode() if entry.food else ""
            })
        except:
            return jsonify({"error": "Decryption failed"}), 400
    return jsonify({"error": "No key found"}), 401

@app.route('/save_entry', methods=['POST'])
@login_required
def save_entry():
    data = request.json
    date_str = data.get('date')
    content = data.get('content')
    food = data.get('food')
    user_pass = request.cookies.get('user_pass')
    
    if user_pass:
        key = get_encryption_key(user_pass, current_user.salt)
        fernet = Fernet(key)
        
        # Check if entry exists for this date, update if so
        existing_entry = Entry.query.filter_by(user_id=current_user.id, date=date_str).first()
        
        encrypted_content = fernet.encrypt(content.encode())
        encrypted_food = fernet.encrypt(food.encode()) if food else fernet.encrypt(b"")
        
        if existing_entry:
            existing_entry.content = encrypted_content
            existing_entry.food = encrypted_food
        else:
            new_entry = Entry(
                date=date_str,
                content=encrypted_content,
                food=encrypted_food,
                user_id=current_user.id
            )
            db.session.add(new_entry)
        
        db.session.commit()
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

# -- Auth Routes (Same as before) --
# --- Update these specific routes in your app.py ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            # Added "error" category
            flash("Username already taken. Please choose another.", "error") 
            return redirect(url_for('register'))

        salt = os.urandom(16)
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_pw, salt=salt)
        db.session.add(new_user)
        db.session.commit()
        
        # Added "success" category
        flash("Account created successfully! Please login.", "success") 
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            login_user(user)
            resp = make_response(redirect(url_for('index')))
            resp.set_cookie('user_pass', request.form['password'], httponly=True)
            return resp
        
        # Added "error" category
        flash("Incorrect username or password. Please try again.", "error") 
    return render_template('login.html')
@app.route('/logout')
def logout():
    logout_user()
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('user_pass')
    return resp

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)