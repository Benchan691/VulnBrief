from flask import Blueprint

# Initialize the main blueprint
newsletter_blueprint = Blueprint('newsletter', __name__)

# Initialize the auth blueprint
subscription_blueprint = Blueprint('subscription', __name__)
auth_blueprint = Blueprint('auth', __name__)

# Import the views
from . import subscription, newsletter,auth