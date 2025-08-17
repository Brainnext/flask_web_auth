# Import the necessary Flask components and SQLAlchemy
import os
import re
import uuid
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

# Loading environment variable from .env file
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)
# Set a secret key for session management and security
# In a real app, this should be a long, random string.
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# --- Database Configuration ---
# Configure the database file. 'sqlite:///site.db' means a file named
# 'site.db' will be created in the same directory as this script.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
# We don't need to track modifications for this simple example.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the SQLAlchemy object with the app.
db = SQLAlchemy(app)

# Configure a directory for file uploads
app.config['UPLOAD_FOLDER'] = 'static/uploads'
# Create the uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Define allowed file extensions for security
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- User Management with Database ---
# The User model is a class that represents the 'user' table in our database.
# UserMixin provides default implementations for Flask-Login's required methods.
class User(UserMixin, db.Model):
    # 'id' is our primary key.
    id = db.Column(db.Integer, primary_key=True)
    # 'username' is a unique string column.
    username = db.Column(db.String(80), unique=True, nullable=False)
    # 'password_hash' stores the hashed password.
    password_hash = db.Column(db.String(128), nullable=False)

    profile_image_url = db.Column(db.String(255), default='/static/placeholders/user.png')
    # A relationship to the Note model, linking notes to this user
    notes = db.relationship('Note', backref='author', lazy=True)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        # This is a helpful representation for debugging.
        return f'<User {self.username}>'

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.String(50), nullable=False, default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    # Foreign key linking the note to a user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Note('{self.content}', '{self.timestamp}')"

@login_manager.user_loader
def load_user(user_id):
    # Retrieve user by their unique ID from the database
    return User.query.get(int(user_id))


# This function is required by Flask-Login to load a user from the session.
# It now queries the database instead of the in-memory dictionary.
@login_manager.user_loader
def load_user(user_id):
    """
    Loads a user object from the database using their user_id.
    """
    return User.query.get(int(user_id))

# --- Routes ---
# The main homepage
@app.route('/')
def home():
    """
    Renders the beautiful, full-page homepage.
    """
    return render_template('index.html')

# The sign-up page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Handles user sign-up by adding a new user to the database.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Check if password match
        if password != confirm_password:
            return render_template ('signup.html' , error_message="password do not match. Please try again.")
        
        # Check for password strength
        if len(password) < 6 :
            return render_template ('signup.html', error_message="password must be at least 6 characters")
        
        # Check if password contains both letters and numbers using regex
        if not re.search(r"[a-zA-Z]", password) or not re.search(r"[0-9]", password):
            return render_template ("signup.html", error_message="Password must be a mix of letters and numbers!")

        # Check if the username already exists in the database
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template ("signup.html" , error_message="Username already exists. Please try another.")
            

        # Create a new User object and set the hashed password
        password_hash = generate_password_hash(password)
        new_user = User(username=username, password_hash=password_hash)
        

        # Add the new user to the database session and commit the changes
        db.session.add(new_user)
        db.session.commit()

        # Redirect to the login page after successful sign-up
        return redirect(url_for('login'))

    return render_template('signup.html')

# The login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login by authenticating against the database.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Find the user by username in the database
        user = User.query.filter_by(username=username).first()

        # Check if the user exists and the password is correct
        if user and check_password_hash(user.password_hash, password):
            # Log the user in using Flask-Login's function
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template ('login.html', error_message="Login failed. Check your username and password.")

    return render_template('login.html')

# The dashboard page, restricted to authenticated users
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Renders the dashboard page for logged-in users.
    """
    return render_template('dashboard.html', username=current_user.username, notes=current_user.notes, profile_image=current_user.profile_image_url)

@app.route('/add_note', methods=['POST'])
@login_required
def add_note():
    note_content = request.form.get('note_content')
    if note_content:
        # Create a new Note object and associate it with the current user
        new_note = Note(content=note_content, author=current_user)
        # Add the note to the database session and commit
        db.session.add(new_note)
        db.session.commit()
        flash('Note added successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_note', methods=['POST'])
@login_required
def delete_note():
    # Get the note ID from the hidden form input
    note_id = request.form.get('note_id')
    # Use get_or_404 to handle cases where the note doesn't exist
    note = Note.query.get_or_404(note_id)

    # Security check: Ensure the current user is the author of the note
    if note.user_id != current_user.id:
        flash('You do not have permission to delete this note.', 'error')
        abort(403) # Forbidden

    db.session.delete(note)
    db.session.commit()
    flash('Note deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/update_name', methods=['POST'])
@login_required
def update_name():
    new_name = request.form.get('new_username')
    if new_name:
        # Update the username in the database
        current_user.username = new_name
        db.session.commit()
        flash('Display name updated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    new_password = request.form.get('new_password')
    if new_password:
        # Update the password hash in the database
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Password updated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    # Check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if the file is allowed
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        # Update the user's profile with the new image URL
        current_user.profile_image_url = url_for('uploaded_file', filename=unique_filename)
        db.session.commit()
        flash('Profile picture uploaded successfully!', 'success')
    else:
        flash('Invalid file type. Only PNG, JPG, JPEG, and GIF are allowed.', 'error')
    
    return redirect(url_for('dashboard'))

# A route to serve uploaded files from the static directory
@app.route('/static/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# The logout route
@app.route('/logout')
@login_required
def logout():
    """
    Logs the user out and redirects to the home page.
    """
    logout_user()
    return redirect(url_for('home'))

# Main entry point to run the application
if __name__ == '__main__':
    # This is a crucial line for the initial setup!
    # It creates the database file and all defined tables.
    # Run this once to initialize the database, then you can comment it out.
    with app.app_context():
        db.create_all()
    app.run(debug=True)
