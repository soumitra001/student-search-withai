from flask import Flask, render_template, request, redirect, url_for, flash ,session
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask_sqlalchemy import SQLAlchemy
import re
import openai
from openai import OpenAI

app = Flask(__name__)
app.secret_key = 'your_secret_key'
client = OpenAI(api_key='API_KEY')


# Flush socket in browser
# chrome://net-internals/#sockets [Flush socket pools]

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database file will be created
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable track modifications to save memory
db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    studentname = db.Column(db.String(100),nullable=False)
    studentclass = db.Column(db.String(10),nullable=False)
    username = db.Column(db.String(100),unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Create the database and tables
with app.app_context():
    db.create_all()

# In-memory database simulation
users_db = {}

# Email validation function
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

# Password validation function
def is_valid_password(password):
    if len(password) < 6:
        return False
    return True
 
@app.route('/')
def home():
    return render_template('login.html')
 
@app.route('/register', methods=['POST','GET'])
def register():
    studentname = request.form['studentname']
    studentclass = request.form['studentclass'] 
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    # Validate form data
    if not username or not email or not password:
        flash('Please fill out all fields!')
        return redirect(url_for('home'))
    
    if not is_valid_email(email):
        flash('Invalid email address!')
        return redirect(url_for('home'))

    if not is_valid_password(password):
        flash('Password must be at least 6 characters long!')
        return redirect(url_for('home'))

    if password != confirm_password:
        flash('Passwords do not match!')
        return redirect(url_for('home'))

    if email in users_db:
        flash('Email is already registered!')
        return redirect(url_for('home'))

    # Hash the password and store the user
    hashed_password = generate_password_hash(password)

    users_db[email] = {'username': username, 'password': hashed_password,'studentname':studentname}
    new_user = User(username=username,studentname=studentname,studentclass=studentclass, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    flash('Registration successful!')
    return redirect(url_for('home'))

@app.route('/registerpage')
def registerpage():
    return render_template('register.html')
    

@app.route('/users')
def get_users():
    users = User.query.all()  # Query all users from the User table
    return render_template('users.html', users=users)


@app.route('/login')
def loginpage():
     return render_template('login.html')

@app.route('/loginaction', methods =['POST','GET'])
def loginaction():
    username = request.form['username']
    input_password=request.form['input_password']
    user_exist = User.query.filter_by(username=username).first()
    if user_exist:
        flash(" User already exists ")  
        if user_exist and check_password_hash(user_exist.password, input_password): 
            flash("Password is correct")
            # Create user session
            session['user'] = user_exist.studentname  # Store Student name in session
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Passwowd is wrong") 
    else:
      flash(" User not found! Please register ")  
     
    return render_template('login.html')  
     
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("You need to log in first!", "error")
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', user=session['user'])

# Chat GPT related functions
@app.route('/openchatgpt')
def openchatgpt():
     return render_template('chatgpt-fe.html')

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if request.method == 'POST':
        user_message = request.form['message']
        chat_response = get_chatgpt_response(user_message)
        return render_template('chatgpt-fe.html', user_message=user_message, chat_response=chat_response)
    return render_template('chatgpt-fe.html')

def get_chatgpt_response(message):
    try:
       response = client.chat.completions.create(
    messages=[
        {
            "role": "user",
            "content": message,
        }
    ],
         model="gpt-4o-mini",)
       print(response.choices[0].message.content)
       return response.choices[0].message.content
    except Exception as e:
         return f"Error: {str(e)}"



if __name__ == '__main__':
    app.run(debug=True)
