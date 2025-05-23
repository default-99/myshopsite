from flask import Flask, request, redirect, session, jsonify # type: ignore
from flask import Flask, render_template, request, redirect, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'myshopsecret'

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# === INIT DB FUNCTION ===
def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        password TEXT,
                        role TEXT
                    )''')
    conn.execute('''CREATE TABLE products (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        description TEXT,
                        price REAL,
                        image TEXT,
                        is_featured INTEGER
                    )''')
    conn.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
    conn.commit()
    conn.close()

# UNCOMMENT ONLY ONCE:
# init_db()

# === LOGIN ===
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            # Get form data
            username = request.form.get('username')
            password = request.form.get('password')
            
            if not username or not password:
                return jsonify({"success": False, "error": "Username and password are required"}), 400
            
            # Database connection
            conn = get_db_connection()
            user = conn.execute(
                'SELECT * FROM users WHERE username = ?', 
                (username,)
            ).fetchone()
            conn.close()
            
            # Verify user exists and password matches
            if user and user['password'] == password:  # In production, use password hashing
                session['logged_in'] = True
                session['user'] = {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user.get('role', 'user')
                }
                
                return jsonify({
                    "success": True,
                    "username": user['username'],
                    "redirect": "/"
                })
            
            return jsonify({
                "success": False, 
                "error": "Invalid username or password"
            }), 401
            
        except Exception as e:
            return jsonify({
                "success": False,
                "error": "An error occurred during login"
            }), 500
    
    # GET request - show login form
    return render_template('login.html')

# === SIGNUP ===
# Signup ka route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            # Form data collect karo
            full_name = request.form['full_name']
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            
            # Validation
            if password != confirm_password:
                return jsonify({"success": False, "error": "Passwords do not match"})
                
            if len(password) < 8:
                return jsonify({"success": False, "error": "Password must be 8+ characters"})
            
            # Database mein save karo
            conn = get_db_connection()
            conn.execute('INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)',
                        (full_name, email, password))  # Production mein password hash karo
            conn.commit()
            
            # Session set karo
            session['user'] = {
                'full_name': full_name,
                'email': email
            }
            
            return jsonify({
                "success": True,
                "message": "Signup successful! Redirecting...",
                "redirect": "/"  # Home page URL
            })
            
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})
    
    return render_template('signup.html')


# Contact Route ko update karein
@app.route('/contact', methods=['GET', 'POST'])  # <- POST method add kiya
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        
        # Yahan aap database mein save kar sakte hain
        print(f"New Contact: {name} <{email}> - {subject}: {message}")
        
        return redirect('/contact?success=1')  # Success message ke liye
    
    # GET request ke liye
    success = request.args.get('success')
    return render_template('contact.html', success=success)

# === ADMIN DASHBOARD ===
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user' not in session or session['user']['role'] != 'admin':
        return redirect('/login')

    conn = get_db_connection()
    if request.method == 'POST':
        conn.execute('INSERT INTO products (name, description, price, image, is_featured) VALUES (?, ?, ?, ?, ?)',
                     (request.form['name'], request.form['description'], request.form['price'],
                      request.form['image'], 1 if 'is_featured' in request.form else 0))
        conn.commit()

    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    return render_template('admin.html', products=products)

# === HOME PAGE ===
@app.route('/')
def home():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products WHERE is_featured=1').fetchall()
    conn.close()
    user = session.get('user') if session.get('logged_in') else None
    return render_template('index.html', logged_in=session.get('logged_in', False))

# === PRODUCTS PAGE ===
@app.route('/products')
def all_products():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()
    return render_template('products.html', products=products, logged_in='user' in session)

# === LOGOUT ===
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# === RUN APP ===
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
