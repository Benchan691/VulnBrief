from . import auth_blueprint
import bcrypt
from flask import render_template,request,redirect,url_for,session
from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017/')
db = client['web']
collection = db['auth']

def verify_password(username, password):
    # Retrieve the user data from MongoDB
    user_data = collection.find_one({'username': username})

    if user_data:
        # Retrieve the hashed password from MongoDB
        hashed_password = user_data['password']

        # Verify the provided password against the stored hash
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            return True
        else:
            return False
    else:
        return False

@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Add your login logic here
        if verify_password(username,password):
            # Successful login
            session['username'] = username
            return redirect(url_for('subscription.subscriptions'))  # Redirect to the dashboard page
        else:
            # Invalid credentials
            return render_template('login.html', error='Invalid email or password')
    
    return render_template('login.html')