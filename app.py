from flask import Flask, request, jsonify, session, render_template, redirect, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-very-strong-secret-key-12345'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # True in production
app.config['TEMPLATES_AUTO_RELOAD'] = True

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        full_name TEXT,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        image TEXT,
        is_featured INTEGER DEFAULT 0
    )''')
    
    # Admin account
    if not conn.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        conn.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            ('admin', 'admin@example.com', generate_password_hash('admin123'), 'admin')
        )
    conn.commit()
    conn.close()

# Uncomment only once to initialize database
# init_db()

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def home():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products WHERE is_featured=1').fetchall()
    conn.close()
    
    return render_template(
        'index.html',
        logged_in='logged_in' in session,
        user=session.get('user'),
        products=products
    )

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        conn = None
        try:
            data = request.form
            if data['password'] != data['confirm_password']:
                return jsonify({"success": False, "error": "Passwords do not match!"})
            if len(data['password']) < 8:
                return jsonify({"success": False, "error": "Password must be 8+ characters!"})
            
            conn = get_db_connection()
            if conn.execute("SELECT 1 FROM users WHERE email=?", (data['email'],)).fetchone():
                return jsonify({"success": False, "error": "Email already exists!"})
            
            username = data['email'].split('@')[0]
            hashed_pw = generate_password_hash(data['password'])
            
            conn.execute(
                "INSERT INTO users (username, email, full_name, password) VALUES (?, ?, ?, ?)",
                (username, data['email'], data['full_name'], hashed_pw)
            )
            conn.commit()
            
            user = conn.execute("SELECT * FROM users WHERE email=?", (data['email'],)).fetchone()
            session.clear()
            session['logged_in'] = True
            session['user'] = dict(user)
            session.modified = True
            
            return jsonify({
                "success": True,
                "message": "Signup successful!",
                "redirect": "/",
                "user": {
                    "id": user['id'],
                    "username": user['username'],
                    "email": user['email']
                }
            })
            
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})
        finally:
            if conn: conn.close()
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            
            if not username or not password:
                return jsonify({"success": False, "error": "Username and password required"}), 400
            
            conn = get_db_connection()
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                session['logged_in'] = True
                session['user'] = dict(user)
                return jsonify({
                    "success": True,
                    "redirect": "/"
                })
            
            return jsonify({"success": False, "error": "Invalid credentials"}), 401
            
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
