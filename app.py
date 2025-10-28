from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3
import os
from datetime import datetime
import zipfile
import io
import hashlib

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'ecocycle-secret-key-2024')

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg', 'ico', 'tiff'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Database initialization
def init_db():
    """Initialize the SQLite database with all required tables"""
    conn = sqlite3.connect('ecocycle.db')
    c = conn.cursor()
    
    # Students table (now users table with authentication)
    c.execute('''CREATE TABLE IF NOT EXISTS students
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  username TEXT UNIQUE,
                  password_hash TEXT,
                  department TEXT NOT NULL,
                  residence TEXT NOT NULL,
                  points INTEGER DEFAULT 0,
                  phone TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Waste logs table with approval and scanning support
    c.execute('''CREATE TABLE IF NOT EXISTS waste_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  student_id INTEGER,
                  waste_type TEXT NOT NULL,
                  quantity INTEGER DEFAULT 1,
                  points_earned INTEGER DEFAULT 10,
                  scanned_code TEXT,
                  approval_status TEXT DEFAULT 'pending',
                  approved_by INTEGER,
                  logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (student_id) REFERENCES students (id),
                  FOREIGN KEY (approved_by) REFERENCES admins (id))''')
    
    # Admins table
    c.execute('''CREATE TABLE IF NOT EXISTS admins
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  full_name TEXT NOT NULL,
                  email TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Rewards table
    c.execute('''CREATE TABLE IF NOT EXISTS rewards
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  description TEXT,
                  points_required INTEGER NOT NULL,
                  image_path TEXT,
                  available INTEGER DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Redeemed rewards table
    c.execute('''CREATE TABLE IF NOT EXISTS redeemed_rewards
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  student_id INTEGER,
                  reward_id INTEGER,
                  redeemed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (student_id) REFERENCES students (id),
                  FOREIGN KEY (reward_id) REFERENCES rewards (id))''')
    
    # Developers table
    c.execute('''CREATE TABLE IF NOT EXISTS developers
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  role TEXT NOT NULL,
                  image_path TEXT,
                  bio TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    conn.commit()
    conn.close()

# Helper function to check file extension
def allowed_file(filename):
    """Check if file has allowed extension - validates image file types"""
    if not filename:
        return False
    # Extract extension and check against allowed types
    if '.' in filename:
        ext = filename.rsplit('.', 1)[1].lower()
        # Accept common image formats and be permissive for flexibility
        return ext in ALLOWED_EXTENSIONS or ext in {'tif', 'tiff', 'jfif', 'pjpeg', 'pjp'}
    return False

# Database helper functions
def get_db():
    """Get database connection"""
    conn = sqlite3.connect('ecocycle.db')
    conn.row_factory = sqlite3.Row
    return conn

# Authentication helper functions
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(password):
    """Hash a password using Werkzeug's secure password hashing"""
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

def admin_required(f):
    """Decorator to require admin login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes

@app.route('/')
def index():
    """User registration landing page"""
    return render_template('index.html')

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    """User login page and authentication"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not all([username, password]):
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
        conn = get_db()
        user = conn.execute('SELECT * FROM students WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if not user or not user['password_hash'] or not check_password_hash(user['password_hash'], password):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        session['student_id'] = user['id']
        session['student_name'] = user['name']
        return jsonify({'success': True, 'redirect': url_for('user_dashboard')})
    
    return render_template('user_login.html')

@app.route('/user/dashboard')
def user_dashboard():
    """User dashboard with stats and quick actions"""
    if 'student_id' not in session:
        return redirect(url_for('user_login'))
    
    conn = get_db()
    student_id = session['student_id']
    
    # Get user details
    user = conn.execute('SELECT * FROM students WHERE id = ?', (student_id,)).fetchone()
    
    # Get total waste logs count
    total_waste_logs = conn.execute('SELECT COUNT(*) as count FROM waste_logs WHERE student_id = ?', 
                                     (student_id,)).fetchone()['count']
    
    # Get redeemed rewards
    redeemed = conn.execute('''SELECT r.name, r.points_required, rr.redeemed_at
                              FROM redeemed_rewards rr
                              JOIN rewards r ON rr.reward_id = r.id
                              WHERE rr.student_id = ?
                              ORDER BY rr.redeemed_at DESC LIMIT 5''', (student_id,)).fetchall()
    
    # Get recent waste logs
    recent_logs = conn.execute('''SELECT * FROM waste_logs 
                                 WHERE student_id = ? 
                                 ORDER BY logged_at DESC LIMIT 5''', (student_id,)).fetchall()
    
    conn.close()
    
    return render_template('user_dashboard.html', 
                         user=user, 
                         total_waste_logs=total_waste_logs,
                         redeemed_rewards=redeemed,
                         recent_logs=recent_logs)

@app.route('/register', methods=['POST'])
def register_student():
    """Register a new user"""
    name = request.form.get('name')
    department = request.form.get('department')
    residence = request.form.get('residence')
    username = request.form.get('username')
    password = request.form.get('password')
    phone = request.form.get('phone')
    
    if not all([name, department, residence, username, password]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    
    conn = get_db()
    
    # Check if username already exists
    existing = conn.execute('SELECT id FROM students WHERE username = ?', (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'success': False, 'message': 'Username already exists'}), 400
    
    # Hash the password
    password_hash = hash_password(password)
    
    # Insert new user
    c = conn.cursor()
    c.execute('INSERT INTO students (name, department, residence, username, phone, password_hash) VALUES (?, ?, ?, ?, ?, ?)',
              (name, department, residence, username, phone, password_hash))
    student_id = c.lastrowid
    conn.commit()
    conn.close()
    
    # Store student ID in session
    session['student_id'] = student_id
    session['student_name'] = name
    
    return jsonify({'success': True, 'redirect': url_for('user_dashboard')})

@app.route('/about')
def about():
    """About page with mission, how it works, and developer profiles"""
    conn = get_db()
    developers = conn.execute('SELECT * FROM developers ORDER BY id').fetchall()
    conn.close()
    return render_template('about.html', developers=developers)

@app.route('/waste-logs')
def waste_logs():
    """Waste logs page showing all waste categories and entries"""
    if 'student_id' not in session:
        return redirect(url_for('index'))
    
    conn = get_db()
    student_id = session['student_id']
    
    # Get all waste logs for current student
    logs = conn.execute('''SELECT * FROM waste_logs 
                          WHERE student_id = ? 
                          ORDER BY logged_at DESC''', (student_id,)).fetchall()
    
    # Get student points
    student = conn.execute('SELECT points FROM students WHERE id = ?', (student_id,)).fetchone()
    points = student['points'] if student else 0
    
    conn.close()
    
    return render_template('waste_logs.html', logs=logs, points=points)

@app.route('/add-waste', methods=['POST'])
def add_waste():
    """Add a new waste log entry with scanning requirement"""
    if 'student_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    waste_type = request.form.get('waste_type')
    quantity = int(request.form.get('quantity', 1))
    scanned_code = request.form.get('scanned_code')
    
    if not waste_type:
        return jsonify({'success': False, 'message': 'Waste type is required'}), 400
    
    if not scanned_code:
        return jsonify({'success': False, 'message': 'Barcode/QR code scan is required'}), 400
    
    # Points per waste item (will be awarded after admin approval)
    points_per_item = 10
    points_earned = quantity * points_per_item
    
    conn = get_db()
    student_id = session['student_id']
    
    # Add waste log with pending approval status
    conn.execute('''INSERT INTO waste_logs (student_id, waste_type, quantity, points_earned, scanned_code, approval_status) 
                   VALUES (?, ?, ?, ?, ?, 'pending')''', (student_id, waste_type, quantity, points_earned, scanned_code))
    
    # Don't update student points yet - points awarded only after admin approval
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Waste log submitted for approval', 'points_earned': points_earned})

@app.route('/available-rewards')
def available_rewards():
    """Show all available rewards"""
    if 'student_id' not in session:
        return redirect(url_for('index'))
    
    conn = get_db()
    rewards = conn.execute('SELECT * FROM rewards WHERE available = 1 ORDER BY points_required').fetchall()
    
    # Get current student points
    student = conn.execute('SELECT points FROM students WHERE id = ?', 
                          (session['student_id'],)).fetchone()
    points = student['points'] if student else 0
    
    conn.close()
    
    return render_template('available_rewards.html', rewards=rewards, points=points)

@app.route('/redeem-reward', methods=['POST'])
def redeem_reward():
    """Redeem a reward"""
    if 'student_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    reward_id = request.form.get('reward_id')
    
    conn = get_db()
    student_id = session['student_id']
    
    # Get reward details
    reward = conn.execute('SELECT * FROM rewards WHERE id = ? AND available = 1', 
                         (reward_id,)).fetchone()
    
    if not reward:
        conn.close()
        return jsonify({'success': False, 'message': 'Reward not available'}), 400
    
    # Get student points
    student = conn.execute('SELECT points FROM students WHERE id = ?', 
                          (student_id,)).fetchone()
    
    if student['points'] < reward['points_required']:
        conn.close()
        return jsonify({'success': False, 'message': 'Insufficient points'}), 400
    
    # Redeem reward
    conn.execute('INSERT INTO redeemed_rewards (student_id, reward_id) VALUES (?, ?)',
                (student_id, reward_id))
    
    # Deduct points
    conn.execute('UPDATE students SET points = points - ? WHERE id = ?',
                (reward['points_required'], student_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Reward redeemed successfully!'})

@app.route('/rewards-dashboard')
def rewards_dashboard():
    """Rewards dashboard with leaderboard and user stats"""
    if 'student_id' not in session:
        return redirect(url_for('index'))
    
    conn = get_db()
    student_id = session['student_id']
    
    # Get current student stats
    student = conn.execute('SELECT * FROM students WHERE id = ?', (student_id,)).fetchone()
    
    # Get redeemed rewards for current student
    redeemed = conn.execute('''SELECT r.name, r.points_required, rr.redeemed_at
                              FROM redeemed_rewards rr
                              JOIN rewards r ON rr.reward_id = r.id
                              WHERE rr.student_id = ?
                              ORDER BY rr.redeemed_at DESC''', (student_id,)).fetchall()
    
    # Get leaderboard (top 10 students)
    leaderboard = conn.execute('''SELECT name, department, points 
                                 FROM students 
                                 ORDER BY points DESC 
                                 LIMIT 10''').fetchall()
    
    conn.close()
    
    return render_template('rewards_dashboard.html', 
                         student=student, 
                         redeemed_rewards=redeemed,
                         leaderboard=leaderboard)

@app.route('/admin/add-reward', methods=['GET', 'POST'])
@admin_required
def add_reward():
    """Admin page to add new rewards"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        points_required = request.form.get('points_required')
        
        # Handle file upload with validation
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'rewards', filename)
                file.save(filepath)
                image_path = f'uploads/rewards/{filename}'
        
        conn = get_db()
        conn.execute('''INSERT INTO rewards (name, description, points_required, image_path)
                       VALUES (?, ?, ?, ?)''', (name, description, points_required, image_path))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Reward added successfully'})
    
    return render_template('add_reward.html')

@app.route('/admin/add-developer', methods=['GET', 'POST'])
@admin_required
def add_developer():
    """Admin page to add developer profiles"""
    if request.method == 'POST':
        name = request.form.get('name')
        role = request.form.get('role')
        bio = request.form.get('bio', '')
        
        # Handle file upload with validation
        image_path = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'developers', filename)
                file.save(filepath)
                image_path = f'uploads/developers/{filename}'
        
        conn = get_db()
        conn.execute('''INSERT INTO developers (name, role, bio, image_path)
                       VALUES (?, ?, ?, ?)''', (name, role, bio, image_path))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Developer added successfully'})
    
    return render_template('add_developer.html')

@app.route('/uploads/<path:filename>')
def serve_uploaded_file(filename):
    """Serve uploaded files (images for rewards and developers)"""
    from flask import send_from_directory
    return send_from_directory('uploads', filename)

@app.route('/download-project')
def download_project():
    """Generate and download the complete project as a ZIP file"""
    memory_file = io.BytesIO()
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add all project files
        for root, dirs, files in os.walk('.'):
            # Skip certain directories
            if any(skip in root for skip in ['.git', '__pycache__', '.pythonlibs', 'node_modules', '.replit']):
                continue
            
            for file in files:
                # Skip database and cache files
                if file.endswith(('.db', '.pyc', '.pyo')):
                    continue
                
                file_path = os.path.join(root, file)
                arcname = file_path.replace('./', '')
                zf.write(file_path, arcname)
    
    memory_file.seek(0)
    
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name='ecocycle_project.zip'
    )

@app.route('/admin/approve-waste/<int:log_id>', methods=['POST'])
@admin_required
def approve_waste_log(log_id):
    """Approve a waste log and award points"""
    conn = get_db()
    
    # Get the waste log
    log = conn.execute('SELECT * FROM waste_logs WHERE id = ?', (log_id,)).fetchone()
    
    if not log:
        conn.close()
        return jsonify({'success': False, 'message': 'Log not found'}), 404
    
    # Approve the log
    conn.execute('''UPDATE waste_logs 
                   SET approval_status = "approved", approved_by = ?
                   WHERE id = ?''', (session['admin_id'], log_id))
    
    # Award points to student
    conn.execute('UPDATE students SET points = points + ? WHERE id = ?',
                (log['points_earned'], log['student_id']))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Waste log approved and points awarded'})

@app.route('/admin/reject-waste/<int:log_id>', methods=['POST'])
@admin_required
def reject_waste_log(log_id):
    """Reject a waste log"""
    conn = get_db()
    
    conn.execute('''UPDATE waste_logs 
                   SET approval_status = "rejected", approved_by = ?
                   WHERE id = ?''', (session['admin_id'], log_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Waste log rejected'})

@app.route('/admin/delete-reward/<int:reward_id>', methods=['POST'])
@admin_required
def delete_reward(reward_id):
    """Delete a reward"""
    conn = get_db()
    conn.execute('DELETE FROM rewards WHERE id = ?', (reward_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Reward deleted successfully'})

@app.route('/admin/delete-developer/<int:dev_id>', methods=['POST'])
@admin_required
def delete_developer(dev_id):
    """Delete a developer profile"""
    conn = get_db()
    conn.execute('DELETE FROM developers WHERE id = ?', (dev_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Developer profile deleted successfully'})

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user/student"""
    conn = get_db()
    
    # Delete related records first
    conn.execute('DELETE FROM waste_logs WHERE student_id = ?', (user_id,))
    conn.execute('DELETE FROM redeemed_rewards WHERE student_id = ?', (user_id,))
    
    # Delete the user
    conn.execute('DELETE FROM students WHERE id = ?', (user_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'User deleted successfully'})

@app.route('/admin/edit-user-points/<int:user_id>', methods=['POST'])
@admin_required
def edit_user_points(user_id):
    """Edit a user's points"""
    new_points = request.form.get('points', type=int)
    
    if new_points is None or new_points < 0:
        return jsonify({'success': False, 'message': 'Invalid points value'}), 400
    
    conn = get_db()
    conn.execute('UPDATE students SET points = ? WHERE id = ?', (new_points, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Points updated successfully'})

@app.route('/admin/students')
@admin_required
def admin_students():
    """View and manage all students"""
    conn = get_db()
    students = conn.execute('''SELECT s.*, 
                              (SELECT COUNT(*) FROM waste_logs WHERE student_id = s.id AND approval_status = "approved") as total_logs
                              FROM students s 
                              ORDER BY s.points DESC''').fetchall()
    conn.close()
    
    return render_template('admin_students.html', students=students)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Comprehensive admin dashboard with analytics"""
    conn = get_db()
    
    total_students = conn.execute('SELECT COUNT(*) as count FROM students').fetchone()['count']
    total_waste_logs = conn.execute('SELECT COUNT(*) as count FROM waste_logs').fetchone()['count']
    pending_approvals = conn.execute('SELECT COUNT(*) as count FROM waste_logs WHERE approval_status = "pending"').fetchone()['count']
    total_rewards = conn.execute('SELECT COUNT(*) as count FROM rewards').fetchone()['count']
    total_points_distributed = conn.execute('SELECT SUM(points) as total FROM students').fetchone()['total'] or 0
    
    # Convert query results to dicts
    def rows_to_dicts(rows):
        return [dict(r) for r in rows]

    recent_students = rows_to_dicts(conn.execute(
        'SELECT * FROM students ORDER BY created_at DESC LIMIT 10').fetchall())
    
    pending_logs = rows_to_dicts(conn.execute('''
        SELECT wl.*, s.name as student_name, s.department 
        FROM waste_logs wl
        JOIN students s ON wl.student_id = s.id
        WHERE wl.approval_status = "pending"
        ORDER BY wl.logged_at DESC
    ''').fetchall())
    
    top_students = rows_to_dicts(conn.execute(
        'SELECT * FROM students ORDER BY points DESC LIMIT 5').fetchall())
    
    waste_stats = rows_to_dicts(conn.execute('''
        SELECT waste_type, COUNT(*) as count, SUM(quantity) as total_quantity
        FROM waste_logs
        WHERE approval_status = "approved"
        GROUP BY waste_type
    ''').fetchall())
    
    conn.close()
    
    return render_template('admin_dashboard.html',
                           total_students=total_students,
                           total_waste_logs=total_waste_logs,
                           pending_approvals=pending_approvals,
                           total_rewards=total_rewards,
                           total_points_distributed=total_points_distributed,
                           recent_students=recent_students,
                           pending_logs=pending_logs,
                           top_students=top_students,
                           waste_stats=waste_stats)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page and authentication"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not all([username, password]):
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
        conn = get_db()
        admin = conn.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if not admin or not admin['password_hash'] or not check_password_hash(admin['password_hash'], password):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        session['admin_id'] = admin['id']
        session['admin_name'] = admin['full_name']
        session['admin_username'] = admin['username']
        return jsonify({'success': True, 'redirect': url_for('admin_dashboard')})
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_username', None)
    return redirect(url_for('admin_login'))

@app.route('/logout')
def logout():
    """Log out current student"""
    session.clear()
    return redirect(url_for('index'))

# Initialize database on startup
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
