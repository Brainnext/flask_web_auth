from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

# Initialize the flask application
app = Flask(__name__)

app.config['SECRET_KEY'] = 'Y248af9b9bed960151c80b152b6b5fc77787ff41ced9312798b83f2f66b9d2a88'

# Database Configuration

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialise the SQLAlchemy object with the app

db = SQLAlchemy(app)

# ---- User Management with Database ----

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)

    password = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        """
        Helpful representation for debugging
        """
        return f'<user> {self.username}'


# Setup Flask-Login

login_Manager = LoginManager()
login_Manager.init_app(app)
login_Manager.login_view = 'login'


# Loading a user from session querying the database

@login_Manager.user_loader
def load_user(user_id):
    """
    Loads a user object from the database using their user_id
    """
    
    return User.query.get(int(user_id))

# Routes
# Main homepage

@app.route('/')
def home():
    """
    Renders the homepae
    """

    return render_template("index.html")

# Routing the sign up page

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Handles user sign up by adding a new user to the db
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if exisitng username already exists in the database
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists. Please try another.", 400
        
        # Create a new user object and set the hashed password
        password_hash = generate_password_hash(password)
        new_user = User(username=username, password_hash=password_hash)

        # Add the new user to the db and commit the change
        db.session.add(new_user)
        db.session.commit()

        #redirect to login page after successsful sign up

        return redirect(url_for('login'))

    return render_template('signup.html')


# The login page

@app.route('/login', methods=['GET' 'POST'])
def login():
    """
    Handles the user auth against the db
    """

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Find user in the db
        user = User.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if user and check_password_hash(user.pqssword_hash, password):
            # Allow the user access
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return "Login failed. Check your username and password.", 401

    return render_template('login.html')


# Dashboard page just for autheticated users
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Render the dashboard page to authenticated users alone
    """

    return render_template('dashboard.html', username=current_user.username)

# THE logot route

@app.route('/logout')
@login_required
def logout():
    """
    Logs out te user and redirects back to homepage
    """
    logout_user()
    return redirect(url_for('home'))


# Main entry point to run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)