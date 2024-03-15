import hashlib
from markupsafe import Markup
import json
import secrets
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
import subprocess
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, username, password_hash):
        self.id = username
        self.password_hash = password_hash

def load_users():
    with open('users.json', 'r') as users:
        users_data = json.load(users)
    users = {}
    for username, data in users_data.items():
        users[username] = User(username, data['password_hash'])
    return users

users = load_users()

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route('/')
def home():
    return 'The opsi script is running.'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and hashlib.md5(password.encode()).hexdigest() == user.password_hash:
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid login')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.id)

@app.route('/dashboard/execute_command', methods=['POST'])
@login_required
def command_page():
    if request.method == 'POST':
        command = request.form['command']
        try:
            result_bytes = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            result_text = result_bytes.decode('utf-8', 'ignore')
            formatted_result = Markup(f"<pre>{result_text}</pre>")
            flash(formatted_result)
        except subprocess.CalledProcessError as e:
            error_text = e.output.decode('utf-8', 'ignore')
            formatted_error = Markup(f"<pre style='color: #ff5722;'>{error_text}</pre>")
            flash(formatted_error)
    return render_template('dashboard.html', username=current_user.id)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
