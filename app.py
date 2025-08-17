# Import the necessary Flask components and SQLAlchemy
import os
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

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

    def __repr__(self):
        # This is a helpful representation for debugging.
        return f'<User {self.username}>'

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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

        # Check if the username already exists in the database
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists. Please try another.", 400

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
            return "Login failed. Check your username and password.", 401

    return render_template('login.html')

# The dashboard page, restricted to authenticated users
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Renders the dashboard page for logged-in users.
    """
    return render_template('dashboard.html', username=current_user.username)

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
