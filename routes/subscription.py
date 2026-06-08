from . import subscription_blueprint
from flask import render_template, request, redirect, url_for, jsonify, session, current_app
from functools import wraps
import json
from pymongo import MongoClient


client = MongoClient('mongodb://localhost:27017/')
db = client['web']
collection = db['subscriptions']

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@subscription_blueprint.route('/subscriptions')
@login_required
def subscriptions():
    with open(current_app.config['SOURCES_CONFIG'], 'r') as f:
        sources = json.load(f)
    return render_template('subscriptions.html',sources=sources)

@subscription_blueprint.route('/get_subscriptions')
@login_required
def get_subscriptions():
    data = list(collection.find({},{'_id': 0}))
    return jsonify({"data":data})

@subscription_blueprint.route('/add_subscription', methods=['POST'])
@login_required
def add_subscription():
    email = (request.form['email']).strip()
    team = (request.form['team']).strip()
    subscriptions = request.form.getlist('subscriptions')
    data = collection.find_one({"email":email})
    if (data == None):
        collection.insert_one({"email":email,"team":team,'subscriptions': subscriptions,'enabled':False})
    else:
        collection.update_one({"email":data['email']}, {'$set': {'subscriptions': subscriptions}})
    return redirect(url_for('subscription.subscriptions'))

@subscription_blueprint.route('/toggle', methods=['POST'])
@login_required
def toggle():
    data = request.get_json()
    collection.update_one({"email":data['email']}, {'$set': {'enabled': data['enabled']}})
    return "success"

@subscription_blueprint.route('/toggle_report', methods=['POST'])
@login_required
def toggle_report():
    data = request.get_json()
    collection.update_one({"email":data['email']}, {'$set': {'report': data['enabled']}})
    return "success"

@subscription_blueprint.route('/remove_subscription', methods=['POST'])
@login_required
def remove_subscription():
    data = request.get_json()
    collection.delete_one({"email":data['email']})
    return "success"

@subscription_blueprint.route('/edit_subscription', methods=['POST'])
def edit_subscription():
    data = request.get_json()
    collection.update_one({"email":data['email']}, {'$set': {'subscriptions': data['subscriptions']}})
    return 'Dictionary updated successfully'
