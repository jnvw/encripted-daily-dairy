import base64
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dairy_diary.db'
db = SQLAlchemy(app)

# Login Manager setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False) # In production, use hashing!
    salt = db.Column(db.LargeBinary, nullable=False)

class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(10), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- Encryption Helper ---
def get_fernet_key(password, salt):
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        salt = b'some_static_or_dynamic_salt' # Ideally unique per user
        new_user = User(username=request.form['username'], password=request.form['password'], salt=salt)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return '''<form method="post">User: <input name="username"> Pass: <input name="password" type="password"><button>Reg</button></form>'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username'], password=request.form['password']).first()
        if user:
            login_user(user)
            return redirect(url_for('index'))
    return '''<form method="post">User: <input name="username"> Pass: <input name="password" type="password"><button>Login</button></form>'''

@app.route('/')
@login_required
def index():
    # Load entries for the user (Decryption happens in the template or route)
    return "Welcome to your Dairy Diary! <a href='/add'>Add Entry</a>"

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_entry():
    if request.method == 'POST':
        content = request.form['content']
        key = get_fernet_key(current_user.password, current_user.salt)
        fernet = Fernet(key)
        
        encrypted = fernet.encrypt(content.encode())
        new_entry = Entry(date=datetime.now().strftime('%Y-%m-%d'), encrypted_content=encrypted, user_id=current_user.id)
        
        db.session.add(new_entry)
        db.session.commit()
        flash("Entry Saved!")
        return redirect(url_for('index'))
    return '<form method="post"><textarea name="content"></textarea><button>Save</button></form>'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)