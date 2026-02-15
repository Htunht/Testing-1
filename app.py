import os
from datetime import datetime
from functools import wraps

from flask import (
    Flask, abort, flash, redirect, render_template, 
    request, url_for, send_from_directory
)
from flask_login import (
    LoginManager, current_user, login_required, 
    login_user, logout_user
)
from werkzeug.utils import secure_filename

from config import Config
from models import db, User, Project

# ==========================================
# 1. CONFIGURATION & SETUP
# ==========================================

app = Flask(__name__)
app.config.from_object(Config)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed extensions (optional security measure)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# ==========================================
# 2. HELPERS & DECORATORS
# ==========================================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# 3. ROUTES
# ==========================================

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html') 

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        if User.query.count() == 0:
            user.role = 'admin'
            flash('First user registered! You are now an Admin.', 'success')
        else:
            flash('Registration successful! Please login.', 'success')

        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_projects = Project.query.filter_by(owner_id=current_user.id).order_by(Project.updated_at.desc()).all()
    return render_template('dashboard.html', projects=user_projects)

@app.route('/projects/new', methods=['GET', 'POST'])
@login_required
def new_project():
    if request.method == 'POST':
        title = request.form.get('title')
        desc = request.form.get('description')
        cat = request.form.get('category')
        status = request.form.get('status')
        
        # Handle File Upload
        filename = None
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # To prevent duplicate overwrites, you might append a timestamp in a real app
                # For now, we save directly
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        project = Project(title=title, description=desc, category=cat, status=status, filename=filename, owner=current_user)
        db.session.add(project)
        db.session.commit()
        flash('Project created successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('project_new.html')

@app.route('/projects/<int:id>')
@login_required
def view_project(id):
    project = Project.query.get_or_404(id)
    if project.owner_id != current_user.id and not current_user.is_admin:
        abort(403)
    return render_template('project_view.html', project=project)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    # Security: Ensure user has access to a project containing this file, or is admin
    # For simplicity in this demo, we allow logged-in users to download known filenames
    # In production, query the DB to check if current_user owns a project with this filename
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/projects/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(id):
    project = Project.query.get_or_404(id)
    if project.owner_id != current_user.id:
        abort(403)
        
    if request.method == 'POST':
        project.title = request.form.get('title')
        project.description = request.form.get('description')
        project.category = request.form.get('category')
        project.status = request.form.get('status')
        
        # Handle File Update (Optional: overwrite existing)
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                project.filename = filename

        db.session.commit()
        flash('Project updated!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('project_edit.html', project=project)

@app.route('/projects/<int:id>/delete')
@login_required
def delete_project(id):
    project = Project.query.get_or_404(id)
    if project.owner_id != current_user.id:
        abort(403)
    
    # Optional: Delete the actual file from os.remove() here if desired
    
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users = User.query.all()
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('admin_dashboard.html', users=users, projects=projects)

@app.route('/admin/user/<int:id>/role')
@admin_required
def toggle_role(id):
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash("You cannot change your own role.", "error")
        return redirect(url_for('admin_dashboard'))
    
    if user.role == 'admin':
        user.role = 'user'
    else:
        user.role = 'admin'
    db.session.commit()
    flash(f'Role for {user.username} updated.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:id>/delete')
@admin_required
def admin_delete_user(id):
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash("You cannot delete yourself.", "error")
        return redirect(url_for('admin_dashboard'))
        
    db.session.delete(user)
    db.session.commit()
    flash(f'User deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/project/<int:id>/delete')
@admin_required
def admin_delete_project(id):
    project = Project.query.get_or_404(id)
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted by admin.', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("----------------------------------------------------------------")
        print("Project Hub Started.")
        print("----------------------------------------------------------------")
    
    app.run(debug=True, port=5001)