from . import auth_blueprint
import bcrypt
from flask import render_template,request,redirect,url_for,session
from pymongo.errors import PyMongoError
from mongo import get_web_database

def verify_password(username, password):
    # Retrieve the user data from MongoDB
    user_data = get_web_database()['auth'].find_one({'username': username})

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
        try:
            if verify_password(username,password):
                session['username'] = username
                return redirect(url_for('subscription.subscriptions'))
            return render_template('login.html', error='Invalid email or password')
        except PyMongoError:
            return render_template(
                'login.html',
                error='Unable to connect to the authentication database.',
            ), 503
    
    return render_template('login.html')
