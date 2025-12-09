from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import os
import io
import base64
import pickle
import face_recognition
import numpy as np
from PIL import Image
import time
import math
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, template_folder=".", static_folder="static")

# ===== ENVIRONMENT CONFIGURATION =====
ENV = os.environ.get('FLASK_ENV', 'development')
app.config['ENV'] = ENV

# Secret key
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

# ===== DATABASE CONFIGURATION =====
if ENV == 'production':
    DATABASE_URL = os.environ.get('DATABASE_URL')
    if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    
    if not DATABASE_URL:
        # Fallback for build process if env var isn't available yet
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shuttle.db'
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    DB_PATH = os.path.join(BASEDIR, 'shuttle.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}

db = SQLAlchemy(app)

# Comprehensive VIT College Route
COLLEGE_ROUTE = [
    (12.9692, 79.1559), (12.9698, 79.1565), (12.9705, 79.1571), (12.9710, 79.1577), (12.9715, 79.1583),
    (12.9720, 79.1590), (12.9725, 79.1596), (12.9730, 79.1602), (12.9735, 79.1608), (12.9740, 79.1614),
    (12.9745, 79.1620), (12.9750, 79.1626), (12.9755, 79.1632), (12.9760, 79.1638), (12.9765, 79.1644),
    (12.9770, 79.1650), (12.9775, 79.1656), (12.9780, 79.1662), (12.9785, 79.1668), (12.9790, 79.1674),
    (12.9795, 79.1680), (12.9800, 79.1686), (12.9805, 79.1692), (12.9810, 79.1698), (12.9815, 79.1704),
    (12.9820, 79.1710), (12.9825, 79.1716), (12.9830, 79.1722), (12.9835, 79.1728), (12.9840, 79.1734),
    (12.9835, 79.1740), (12.9830, 79.1746), (12.9825, 79.1752), (12.9820, 79.1758), (12.9815, 79.1764),
    (12.9810, 79.1770), (12.9805, 79.1776), (12.9800, 79.1782), (12.9795, 79.1788), (12.9790, 79.1794),
    (12.9785, 79.1800), (12.9780, 79.1806), (12.9775, 79.1812), (12.9770, 79.1805), (12.9765, 79.1798),
    (12.9760, 79.1791), (12.9755, 79.1784), (12.9750, 79.1777), (12.9745, 79.1770), (12.9740, 79.1763),
    (12.9735, 79.1756), (12.9730, 79.1749), (12.9725, 79.1742), (12.9720, 79.1735), (12.9715, 79.1728),
    (12.9710, 79.1721), (12.9705, 79.1714), (12.9700, 79.1707), (12.9695, 79.1700), (12.9692, 79.1559),
]

STUDENT_LOCATIONS = {
    'main_gate': {'name': 'Main Gate', 'coords': (12.9692, 79.1559)},
    'mb_block': {'name': 'MB Block (Mudaliar)', 'coords': (12.9710, 79.1577)},
    'library': {'name': 'Central Library', 'coords': (12.9745, 79.1620)},
    'cdmm': {'name': 'CDMM Building', 'coords': (12.9720, 79.1590)},
    'smv': {'name': 'SMV Building', 'coords': (12.9725, 79.1596)},
    'tech_tower': {'name': 'Technology Tower', 'coords': (12.9735, 79.1608)},
    'gandhi_block': {'name': 'Gandhi Block', 'coords': (12.9750, 79.1626)},
    'sports': {'name': 'Sports Complex', 'coords': (12.9755, 79.1632)},
    'a_block': {'name': 'A Block Hostel', 'coords': (12.9770, 79.1650)},
    'food_court': {'name': 'Food Court', 'coords': (12.9805, 79.1776)},
    # (Add other locations as needed from your list)
}

HOSTEL_LOCATION = (12.9840, 79.1734)
LIBRARY_LOCATION = (12.9745, 79.1620)
ACADEMIC_CENTER = (12.9720, 79.1590)

# ===== DATABASE MODELS =====

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    reason = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    registration = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(150), unique=True)
    balance = db.Column(db.Float, default=0.0)
    face_encoding = db.Column(db.LargeBinary) # Storing pickle bytes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    transactions = db.relationship('Transaction', backref='student', lazy=True, cascade="all, delete-orphan")

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ShuttleLocation(db.Model):
    __tablename__ = 'shuttle_location'
    shuttle_id = db.Column(db.String(50), primary_key=True)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ===== HELPER FUNCTIONS =====

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

def haversine_distance(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat/2) * math.sin(dlat/2) +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon/2) * math.sin(dlon/2))
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

def calculate_eta(current_pos, destination, avg_speed_kmh=25):
    distance_km = haversine_distance(current_pos[0], current_pos[1], destination[0], destination[1])
    time_hours = distance_km / avg_speed_kmh
    return max(int(time_hours * 60), 1)

def init_database():
    with app.app_context():
        db.create_all()
        
        # Default Admin
        if not User.query.filter_by(role='admin').first():
            default_admin = User(
                name='Default Admin',
                email='admin@vit.edu',
                password=generate_password_hash('admin123'),
                role='admin',
                is_approved=True
            )
            db.session.add(default_admin)
            print("Default admin created")

        # Initialize Shuttle
        if not ShuttleLocation.query.get('shuttle_01'):
            shuttle = ShuttleLocation(
                shuttle_id='shuttle_01',
                latitude=COLLEGE_ROUTE[0][0],
                longitude=COLLEGE_ROUTE[0][1]
            )
            db.session.add(shuttle)
            print("Shuttle initialized")
            
        db.session.commit()

# ===== ROUTES =====

@app.route("/")
def index():
    try:
        total_students = Student.query.count()
        total_balance = db.session.query(db.func.sum(Student.balance)).scalar() or 0
        total_transactions = Transaction.query.count()
    except:
        total_students, total_balance, total_transactions = 0, 0, 0
    
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
        # Check if student exists in Student DB but not User DB (migration case)
        student = Student.query.filter_by(email=email).first()
        if student:
            # Create user account for existing student
            hashed_password = generate_password_hash(password)
            new_user = User(
                name=student.name,
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
        else:
            flash('No student record found. Please register first.', 'error')
            return redirect(url_for('student_register'))
    
    return redirect(url_for('index'))

@app.route("/student_register", methods=["GET", "POST"])
def student_register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").lower().strip()
        password = request.form.get("password", "")
        
        if User.query.filter_by(email=email).first() or Student.query.filter_by(email=email).first():
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
            if not face_encodings:
                return render_template("student_register.html", error="No face detected")
            if len(face_encodings) > 1:
                return render_template("student_register.html", error="Multiple faces detected")
            
            face_encoding = face_encodings[0]
            
            # Check for duplicate faces
            all_students = Student.query.all()
            existing_encodings = []
            for s in all_students:
                if s.face_encoding:
                    try:
                        existing_encodings.append(pickle.loads(s.face_encoding))
                    except: continue
            
            if existing_encodings:
                matches = face_recognition.compare_faces(existing_encodings, face_encoding, tolerance=0.6)
                if any(matches):
                    return render_template("student_register.html", error="Face already registered")
            
            # Create Student Record
            reg_number = f"STU{int(time.time())}"
            new_student = Student(
                name=name,
                registration=reg_number,
                email=email,
                balance=0.0,
                face_encoding=pickle.dumps(face_encoding)
            )
            db.session.add(new_student)
            
            # Create User Login
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
            
            flash("Registration successful!", "success")
            return redirect(url_for("student_dashboard"))
            
        except Exception as e:
            return render_template("student_register.html", error=f"Error: {str(e)}")
    
    return render_template("student_register.html")

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "").lower().strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "")
    
    user = User.query.filter_by(email=email, role=role).first()
    
    if user and check_password_hash(user.password, password):
        if not user.is_approved:
            flash('Account pending approval.', 'error')
            return redirect(url_for('index'))
        
        session['user_id'] = user.id
        session['email'] = user.email
        session['role'] = user.role
        session['name'] = user.name
        
        if role == 'admin': return redirect(url_for('admin_dashboard'))
        elif role == 'shuttle': return redirect(url_for('shuttle_dashboard'))
        
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
        flash('Email already exists.', 'error')
        return redirect(url_for('index'))
    
    try:
        new_request = User(
            name=name, email=email,
            password=generate_password_hash(password),
            role=role, is_approved=False, reason=reason
        )
        db.session.add(new_request)
        db.session.commit()
        flash('Request submitted.', 'success')
    except:
        flash('Request failed.', 'error')
    return redirect(url_for('index'))

@app.route("/logout")
def logout():
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('index'))

@app.route("/student")
@login_required(role="student")
def student_dashboard():
    student = Student.query.filter_by(email=session['email']).first()
    balance = student.balance if student else 0
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
    students = Student.query.order_by(Student.name).all()
    
    # Get recent transactions with student info
    transactions = db.session.query(Transaction, Student).join(Student).order_by(Transaction.timestamp.desc()).limit(10).all()
    formatted_transactions = []
    for t, s in transactions:
        formatted_transactions.append({
            'name': s.name,
            'amount': t.amount,
            'transaction_type': t.transaction_type,
            'timestamp': t.timestamp
        })

    return render_template("admin_dashboard.html",
                         pending_users=pending_users,
                         approved_drivers=approved_drivers,
                         students=students,
                         transactions=formatted_transactions)

@app.route("/admin/approve/<int:user_id>")
@login_required(role="admin")
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_approved = True
    db.session.commit()
    flash(f'{user.name} approved.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/reject/<int:user_id>")
@login_required(role="admin")
def reject_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'Request rejected.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/delete_student/<int:student_id>", methods=["POST"])
@login_required(role="admin")
def delete_student(student_id):
    student = Student.query.get_or_404(student_id)
    # Also delete login user if exists
    user = User.query.filter_by(email=student.email, role='student').first()
    if user: db.session.delete(user)
    db.session.delete(student)
    db.session.commit()
    flash('Student deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/delete_driver/<int:user_id>", methods=["POST"])
@login_required(role="admin")
def delete_driver(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'shuttle':
        db.session.delete(user)
        db.session.commit()
        flash('Driver removed.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route("/register", methods=["GET", "POST"])
@login_required(role="admin")
def register():
    if request.method == "POST":
        # (Similar logic to student_register but for admin usage)
        # For brevity, reusing student_register template is fine, 
        # or implement full admin manual registration here following the same pattern
        pass
    return render_template("register.html")

@app.route("/create_payment_order", methods=["POST"])
@login_required(role="student")
def create_payment_order():
    amount = int(request.form.get("amount", 50)) * 100
    order_id = f"order_demo_{int(time.time())}"
    return jsonify({'success': True, 'order_id': order_id, 'amount': amount})

@app.route("/verify_payment", methods=["POST"])
@login_required(role="student")
def verify_payment():
    amount = int(request.form.get('amount')) // 100
    student = Student.query.filter_by(email=session['email']).first()
    
    if student:
        student.balance += amount
        txn = Transaction(student_id=student.id, amount=amount, transaction_type="balance_add")
        db.session.add(txn)
        db.session.commit()
        flash(f'Added ₹{amount}', 'success')
    
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
    if not data_url: return jsonify({"ok": False, "error": "No image"}), 400
    
    try:
        header, b64data = data_url.split(",", 1)
        img_np = np.array(Image.open(io.BytesIO(base64.b64decode(b64data))).convert("RGB"))
        encs = face_recognition.face_encodings(img_np)
        if not encs: return jsonify({"ok": False, "error": "No face found"}), 200
        
        probe = encs[0]
        students = Student.query.all()
        known_encs = []
        meta = []
        
        for s in students:
            if s.face_encoding:
                try:
                    known_encs.append(pickle.loads(s.face_encoding))
                    meta.append(s)
                except: continue
        
        if not known_encs: return jsonify({"ok": False, "error": "No students registered"}), 200
        
        dists = face_recognition.face_distance(known_encs, probe)
        best_idx = int(np.argmin(dists))
        
        if dists[best_idx] > 0.6:
            return jsonify({"ok": False, "error": "No match found"}), 200
            
        student = meta[best_idx]
        FARE = 20.0
        
        if student.balance < FARE:
            return jsonify({"ok": False, "error": "Insufficient balance", "balance": student.balance}), 200
            
        student.balance -= FARE
        txn = Transaction(student_id=student.id, amount=-FARE, transaction_type="shuttle_ride")
        db.session.add(txn)
        db.session.commit()
        
        return jsonify({"ok": True, "match": {"name": student.name, "reg": student.registration}, "fare": FARE, "new_balance": student.balance}), 200
        
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ===== SHUTTLE TRACKING ROUTES =====

@app.route("/track_shuttle")
def track_shuttle():
    return render_template("track_shuttle.html", student_locations=STUDENT_LOCATIONS)

@app.route("/location/simulate")
def simulate_shuttle():
    shuttle = ShuttleLocation.query.get('shuttle_01')
    if not shuttle: return jsonify({'success': False, 'error': 'No shuttle found'})
    
    # Find closest point index
    curr_idx = 0
    min_dist = float('inf')
    for i, (lat, lon) in enumerate(COLLEGE_ROUTE):
        d = haversine_distance(shuttle.latitude, shuttle.longitude, lat, lon)
        if d < min_dist:
            min_dist = d
            curr_idx = i
            
    next_idx = (curr_idx + 1) % len(COLLEGE_ROUTE)
    next_pos = COLLEGE_ROUTE[next_idx]
    
    shuttle.latitude = next_pos[0]
    shuttle.longitude = next_pos[1]
    shuttle.timestamp = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True, 'position': next_pos})

@app.route("/location/<shuttle_id>")
def get_shuttle_location(shuttle_id):
    shuttle = ShuttleLocation.query.get(shuttle_id)
    if not shuttle: return jsonify({'error': 'Not found'}), 404
    
    pos = (shuttle.latitude, shuttle.longitude)
    return jsonify({
        'latitude': shuttle.latitude,
        'longitude': shuttle.longitude,
        'eta_minutes': calculate_eta(pos, HOSTEL_LOCATION)
    })

@app.route("/calculate_eta", methods=["POST"])
def calculate_eta_endpoint():
    data = request.get_json()
    loc_key = data.get('location')
    if loc_key not in STUDENT_LOCATIONS: return jsonify({'error': 'Invalid loc'}), 400
    
    shuttle = ShuttleLocation.query.get('shuttle_01')
    if not shuttle: return jsonify({'error': 'Shuttle offline'}), 404
    
    eta = calculate_eta((shuttle.latitude, shuttle.longitude), STUDENT_LOCATIONS[loc_key]['coords'])
    return jsonify({'eta_minutes': eta})

@app.route("/start_shuttle")
def start_shuttle():
    shuttle = ShuttleLocation.query.get('shuttle_01')
    if not shuttle:
        shuttle = ShuttleLocation(shuttle_id='shuttle_01', latitude=COLLEGE_ROUTE[0][0], longitude=COLLEGE_ROUTE[0][1])
        db.session.add(shuttle)
    else:
        shuttle.latitude = COLLEGE_ROUTE[0][0]
        shuttle.longitude = COLLEGE_ROUTE[0][1]
    db.session.commit()
    return jsonify({'success': True})

if __name__ == "__main__":
    init_database()
    app.run(host="0.0.0.0", port=int(os.environ.get('PORT', 5000)))