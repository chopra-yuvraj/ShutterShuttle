from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import sqlite3
import os
import io
import base64
import pickle
import face_recognition
import numpy as np
from PIL import Image
import time

app = Flask(__name__, template_folder=".", static_folder=".")
app.secret_key = "your-super-secret-key-change-this-in-production"

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shuttle_auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def get_db_connection():
    conn = sqlite3.connect("shuttle.db")
    conn.row_factory = sqlite3.Row
    return conn

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('index'))
            if role and session.get('role') != role:
                flash('Unauthorized access', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

def init_database():
    with app.app_context():
        db.create_all()
        # Default admin
        if not User.query.filter_by(role='admin', is_approved=True).first():
            default_admin = User(
                name='Default Admin',
                email='admin@vit.edu',
                password=generate_password_hash('admin123'),
                role='admin',
                is_approved=True
            )
            db.session.add(default_admin)
            db.session.commit()
            print("Default admin created: admin@vit.edu / admin123")

    # Ensure campus tables exist and have `email`
    conn = get_db_connection()
    # Create students table if not exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            registration TEXT UNIQUE,
            balance REAL,
            face_encoding BLOB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Add email column if missing
    cols = [c['name'] for c in conn.execute("PRAGMA table_info(students)").fetchall()]
    if 'email' not in cols:
        conn.execute("ALTER TABLE students ADD COLUMN email TEXT")
    # Create transactions
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            amount REAL,
            transaction_type TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(student_id) REFERENCES students(id)
        )
    """)
    conn.commit()
    conn.close()



@app.route("/")
def index():
    conn = get_db_connection()
    try:
        total_students = conn.execute("SELECT COUNT(*) as count FROM students").fetchone()['count'] if conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='students'").fetchone() else 0
        total_balance = conn.execute("SELECT SUM(balance) as total FROM students").fetchone()['total'] or 0
        total_transactions = conn.execute("SELECT COUNT(*) as count FROM transactions").fetchone()['count'] if conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='transactions'").fetchone() else 0
    except:
        total_students = 0
        total_balance = 0
        total_transactions = 0
    conn.close()
    
    return render_template("index.html",
                           total_students=total_students,
                           total_balance=total_balance,
                           total_transactions=total_transactions)

@app.route("/student_auth", methods=["POST"])
def student_auth():
    email = request.form.get("email", "").lower().strip()
    password = request.form.get("password", "")
    
    user = User.query.filter_by(email=email, role='student').first()
    
    if user:
        if check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['email'] = user.email
            session['role'] = user.role
            session['name'] = user.name
            flash('Login successful!', 'success')
            return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid credentials', 'error')
    else:
        try:
            hashed_password = generate_password_hash(password)
            new_user = User(
                name=email.split('@')[0],
                email=email,
                password=hashed_password,
                role='student',
                is_approved=True
            )
            db.session.add(new_user)
            db.session.commit()
            
            session['user_id'] = new_user.id
            session['email'] = new_user.email
            session['role'] = new_user.role
            session['name'] = new_user.name
            
            flash('Account created successfully!', 'success')
            return redirect(url_for('student_dashboard'))
        except Exception:
            flash('Registration failed. Email might already exist.', 'error')
    
    return redirect(url_for('index'))

@app.route("/student_register", methods=["GET", "POST"])  
def student_register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").lower().strip()
        password = request.form.get("password", "")
        
        if User.query.filter_by(email=email).first():
            return render_template("student_register.html", error="Email already exists")
        
        try:
            image_array = None
            if "photo_data" in request.form and request.form["photo_data"]:
                data_url = request.form["photo_data"]
                header, b64data = data_url.split(",", 1)
                binary = base64.b64decode(b64data)
                image = Image.open(io.BytesIO(binary)).convert("RGB")
                image_array = np.array(image)
            elif "photo" in request.files and request.files["photo"].filename != "":
                file = request.files["photo"]
                image = Image.open(file.stream).convert("RGB")
                image_array = np.array(image)
            else:
                return render_template("student_register.html", error="Please provide a photo")

            face_encodings = face_recognition.face_encodings(image_array)
            if len(face_encodings) == 0:
                return render_template("student_register.html", error="No face detected in photo")
            if len(face_encodings) > 1:
                return render_template("student_register.html", error="Multiple faces detected - use single face photo")
            
            face_encoding = face_encodings[0]

            conn = get_db_connection()
            try:
                rows = conn.execute("SELECT face_encoding FROM students").fetchall()
                existing_encodings = []
                for row in rows:
                    try:
                        enc = pickle.loads(row["face_encoding"])
                        existing_encodings.append(enc)
                    except:
                        continue

                matches = face_recognition.compare_faces(existing_encodings, face_encoding, tolerance=0.6)
                if any(matches):
                    conn.close()
                    return render_template("student_register.html", error="Your face is already registered")

                reg_number = f"STU{int(time.time())}"
                
                conn.execute("""
                    INSERT INTO students (name, registration, balance, face_encoding, email)
                    VALUES (?, ?, ?, ?, ?)
                """, (name, reg_number, 0.0, pickle.dumps(face_encoding), email))
                conn.commit()
                conn.close()
                
                hashed_password = generate_password_hash(password)
                new_user = User(
                    name=name,
                    email=email,
                    password=hashed_password,
                    role='student',
                    is_approved=True
                )
                db.session.add(new_user)
                db.session.commit()
                
                session['user_id'] = new_user.id
                session['email'] = new_user.email
                session['role'] = new_user.role
                session['name'] = new_user.name
                
                flash("Registration successful! Add balance to start using shuttle service.", "success")
                return redirect(url_for("student_dashboard"))
                
            except Exception as e:
                conn.close()
                return render_template("student_register.html", error=f"Registration failed: {str(e)}")
                
        except Exception as e:
            return render_template("student_register.html", error=f"Photo processing failed: {str(e)}")
    
    return render_template("student_register.html")

@app.route("/admin/delete_student/<int:student_id>", methods=["POST"])
@login_required(role="admin")
def delete_student(student_id):
    conn = get_db_connection()
    try:
        student = conn.execute("SELECT name, registration, email FROM students WHERE id = ?", (student_id,)).fetchone()
        if not student:
            flash("Student not found", "error")
            return redirect(url_for("admin_dashboard"))
        
        conn.execute("DELETE FROM transactions WHERE student_id = ?", (student_id,))
        conn.execute("DELETE FROM students WHERE id = ?", (student_id,))
        conn.commit()
        
        # Also delete from auth database
        if student['email']:
            user = User.query.filter_by(email=student['email'], role='student').first()
            if user:
                db.session.delete(user)
                db.session.commit()
        
        conn.close()
        flash(f"Student {student['name']} deleted successfully", "success")
    except Exception as e:
        conn.close()
        flash(f"Error deleting student: {str(e)}", "error")
    
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete_driver/<int:user_id>", methods=["POST"])
@login_required(role="admin")
def delete_driver(user_id):
    try:
        user = User.query.get_or_404(user_id)
        if user.role != 'shuttle':
            flash('Can only delete drivers', 'error')
            return redirect(url_for('admin_dashboard'))
        
        driver_name = user.name
        db.session.delete(user)
        db.session.commit()
        flash(f'Driver {driver_name} deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting driver: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "").lower().strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "")
    
    user = User.query.filter_by(email=email, role=role).first()
    
    if user and check_password_hash(user.password, password):
        if not user.is_approved:
            flash('Your account is pending approval. Please contact an admin.', 'error')
            return redirect(url_for('index'))
        
        session['user_id'] = user.id
        session['email'] = user.email
        session['role'] = user.role
        session['name'] = user.name
        
        flash('Login successful!', 'success')
        
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'shuttle':
            return redirect(url_for('shuttle_dashboard'))
    else:
        flash('Invalid credentials', 'error')
    
    return redirect(url_for('index'))

@app.route("/request_access", methods=["POST"])
def request_access():
    name = request.form.get("name", "")
    email = request.form.get("email", "").lower().strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "")
    reason = request.form.get("reason", "")
    
    if User.query.filter_by(email=email).first():
        flash('Email already exists. Try logging in instead.', 'error')
        return redirect(url_for('index'))
    
    try:
        hashed_password = generate_password_hash(password)
        new_request = User(
            name=name,
            email=email,
            password=hashed_password,
            role=role,
            is_approved=False,
            reason=reason
        )
        db.session.add(new_request)
        db.session.commit()
        
        flash(f'Your {role} access request has been submitted for approval.', 'success')
    except Exception:
        flash('Request submission failed. Please try again.', 'error')
    
    return redirect(url_for('index'))

@app.route("/logout")
def logout():
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route("/student")
@login_required(role="student")
def student_dashboard():
    # Get student balance
    conn = get_db_connection()
    try:
        student = conn.execute("SELECT balance FROM students WHERE email = ?", (session['email'],)).fetchone()
        balance = student['balance'] if student else 0
    except:
        balance = 0
    conn.close()
    return render_template("student_dashboard.html", balance=balance)

@app.route("/shuttle")
@login_required(role="shuttle")
def shuttle_dashboard():
    return render_template("shuttle_dashboard.html")

@app.route("/admin")
@login_required(role="admin")
def admin_dashboard():
    pending_users = User.query.filter_by(is_approved=False).all()
    approved_drivers = User.query.filter_by(role='shuttle', is_approved=True).all()
    
    conn = get_db_connection()
    students = []
    transactions = []
    try:
        students = conn.execute("SELECT * FROM students ORDER BY name").fetchall()
        transactions = conn.execute("""
            SELECT t.*, s.name, s.registration 
            FROM transactions t 
            JOIN students s ON t.student_id = s.id 
            ORDER BY t.timestamp DESC 
            LIMIT 10
        """).fetchall()
    except:
        pass
    conn.close()
    
    return render_template("admin_dashboard.html", 
                           pending_users=pending_users,
                           approved_drivers=approved_drivers,
                           students=students,
                           transactions=transactions)

@app.route("/admin/approve/<int:user_id>")
@login_required(role="admin")
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    db.session.commit()
    flash(f'{user.name} ({user.role}) has been approved!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/reject/<int:user_id>")
@login_required(role="admin")
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'{user.name} ({user.role}) request has been rejected.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route("/register", methods=["GET", "POST"])
@login_required(role="admin")
def register():
    if request.method == "POST":
        name = request.form.get("name", "")
        reg_number = request.form.get("registration", "")
        balance = int(request.form.get("balance", 100))
        
        try:
            image_array = None
            if "photo_data" in request.form and request.form["photo_data"]:
                data_url = request.form["photo_data"]
                header, b64data = data_url.split(",", 1)
                binary = base64.b64decode(b64data)
                image = Image.open(io.BytesIO(binary)).convert("RGB")
                image_array = np.array(image)
            elif "photo" in request.files and request.files["photo"].filename != "":
                file = request.files["photo"]
                image = Image.open(file.stream).convert("RGB")
                image_array = np.array(image)
            else:
                return render_template("register.html", error="No photo captured or uploaded")

            face_encodings = face_recognition.face_encodings(image_array)
            if len(face_encodings) == 0:
                return render_template("register.html", error="No face found in image")
            if len(face_encodings) > 1:
                return render_template("register.html", error="Multiple faces found")
            
            face_encoding = face_encodings[0]

            conn = get_db_connection()
            try:
                rows = conn.execute("SELECT face_encoding FROM students").fetchall()
                existing_encodings = []
                for row in rows:
                    try:
                        enc = pickle.loads(row["face_encoding"])
                        existing_encodings.append(enc)
                    except:
                        continue

                matches = face_recognition.compare_faces(existing_encodings, face_encoding, tolerance=0.6)
                if any(matches):
                    conn.close()
                    return render_template("register.html", error="Similar face already registered")

                conn.execute("""
                    INSERT INTO students (name, registration, balance, face_encoding)
                    VALUES (?, ?, ?, ?)
                """, (name, reg_number, balance, pickle.dumps(face_encoding)))
                conn.commit()
                conn.close()
                
                flash("Student registered successfully!", "success")
                return redirect(url_for("admin_dashboard"))
                
            except Exception as e:
                conn.close()
                return render_template("register.html", error=f"Database error: {str(e)}")
                
        except Exception as e:
            return render_template("register.html", error=f"Registration failed: {str(e)}")
    
    return render_template("register.html")

# Demo payment endpoints
@app.route("/create_payment_order", methods=["POST"])
@login_required(role="student")
def create_payment_order():
    amount = int(request.form.get("amount", 50)) * 100
    order_id = f"order_demo_{int(time.time())}"
    return jsonify({
        'success': True,
        'order_id': order_id,
        'amount': amount,
        'key': 'demo_key'
    })

@app.route("/verify_payment", methods=["POST"])
@login_required(role="student")
def verify_payment():
    amount = int(request.form.get('amount')) // 100
    
    conn = get_db_connection()
    try:
        student = conn.execute("SELECT id FROM students WHERE email = ?", (session['email'],)).fetchone()
        if student:
            conn.execute("UPDATE students SET balance = balance + ? WHERE id = ?", (amount, student['id']))
            conn.execute("INSERT INTO transactions (student_id, amount, transaction_type) VALUES (?, ?, ?)", 
                       (student['id'], amount, "balance_add"))
            conn.commit()
            
        conn.close()
        flash(f'Successfully added ₹{amount} to your balance!', 'success')
        
    except Exception as e:
        conn.close()
        flash(f'Payment successful but balance update failed: {str(e)}', 'error')
        
    return redirect(url_for('student_dashboard'))

@app.route("/add_balance", methods=["GET"])
@login_required(role="student")
def add_balance():
    return render_template("add_balance.html")

@app.route("/scan")
@login_required(role="shuttle")
def scan_page():
    return render_template("scan.html")

@app.route("/scan", methods=["POST"])
@login_required(role="shuttle")
def scan_post():
    data_url = request.form.get("photo_data", "")
    if not data_url:
        return jsonify({"ok": False, "error": "No image received"}), 400

    try:
        header, b64data = data_url.split(",", 1)
        img_bytes = base64.b64decode(b64data)
        img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
        img_np = np.array(img)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid image: {e}"}), 400

    encs = face_recognition.face_encodings(img_np)
    if len(encs) == 0:
        return jsonify({"ok": False, "error": "No face found"}), 200
    
    probe = encs[0]
    conn = get_db_connection()
    
    try:
        rows = conn.execute("SELECT id, name, registration, balance, face_encoding FROM students").fetchall()
        known_encs, meta = [], []
        
        for r in rows:
            try:
                enc = pickle.loads(r["face_encoding"])
                known_encs.append(enc)
                meta.append({"id": r["id"], "name": r["name"], "reg": r["registration"], "balance": r["balance"]})
            except:
                continue
        
        if not known_encs:
            conn.close()
            return jsonify({"ok": False, "error": "No enrolled students"}), 200

        dists = face_recognition.face_distance(known_encs, probe)
        best_idx = int(np.argmin(dists))
        best_dist = float(dists[best_idx])
        
        if best_dist > 0.6:
            conn.close()
            return jsonify({"ok": False, "error": "No match found"}), 200

        student = meta[best_idx]
        FARE_AMOUNT = 20.0
        
        conn.execute("BEGIN IMMEDIATE")
        curr_balance = float(conn.execute("SELECT balance FROM students WHERE id = ?", (student["id"],)).fetchone()["balance"])
        
        if curr_balance < FARE_AMOUNT:
            conn.execute("ROLLBACK")
            conn.close()
            return jsonify({"ok": False, "error": "Insufficient balance", "balance": curr_balance}), 200
        
        new_balance = curr_balance - FARE_AMOUNT
        conn.execute("UPDATE students SET balance = ? WHERE id = ?", (new_balance, student["id"]))
        conn.execute("INSERT INTO transactions (student_id, amount, transaction_type) VALUES (?, ?, ?)",
                    (student["id"], -FARE_AMOUNT, "shuttle_ride"))
        conn.commit()
        conn.close()
        
        return jsonify({"ok": True, "match": student, "fare": FARE_AMOUNT, "new_balance": new_balance}), 200
        
    except Exception as e:
        try:
            conn.execute("ROLLBACK")
        except:
            pass
        conn.close()
        return jsonify({"ok": False, "error": f"Transaction failed: {e}"}), 500

if __name__ == "__main__":
    init_database()
    print("ShutterShuttle Server Starting...")
    print("Access at: http://127.0.0.1:5000")
    print("Default Admin: admin@vit.edu / admin123")
    app.run(debug=True, host="0.0.0.0", port=5000)
