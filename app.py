import base64
import os
from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dairy_diary.db'
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
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
    user_entries = Entry.query.filter_by(user_id=current_user.id).all()
    user_pass = request.cookies.get('user_pass')
    
    decrypted_entries = []
    if user_pass:
        key = get_encryption_key(user_pass, current_user.salt)
        fernet = Fernet(key)
        for e in user_entries:
            try:
                decrypted_entries.append({
                    'date': e.date,
                    'content': fernet.decrypt(e.content).decode(),
                    'food': fernet.decrypt(e.food).decode() if e.food else ""
                })
            except Exception:
                decrypted_entries.append({'date': e.date, 'content': "[Decryption Error]", 'food': ""})
    
    return render_template('index.html', entries=decrypted_entries)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists!")
            return redirect(url_for('register'))

        salt = os.urandom(16)
        hashed_pw = generate_password_hash(password)
        
        new_user = User(username=username, password_hash=hashed_pw, salt=salt)
        db.session.add(new_user)
        db.session.commit()
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
        flash("Invalid credentials")
    return render_template('login.html')

@app.route('/add', methods=['POST'])
@login_required
def add_entry():
    content = request.form['content']
    food = request.form['food']
    user_pass = request.cookies.get('user_pass')
    
    if user_pass:
        key = get_encryption_key(user_pass, current_user.salt)
        fernet = Fernet(key)
        new_entry = Entry(
            date=datetime.now().strftime('%Y-%m-%d'),
            content=fernet.encrypt(content.encode()),
            food=fernet.encrypt(food.encode()) if food else fernet.encrypt(b""),
            user_id=current_user.id
        )
        db.session.add(new_entry)
        db.session.commit()
    return redirect(url_for('index'))

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
if __name__ == '__main__':
    with app.app_context():
        # WARNING: This deletes all existing data!
        db.drop_all() 
        db.create_all()
    app.run(debug=True)