from flask import Blueprint

# Initialize the main blueprint
newsletter_blueprint = Blueprint('newsletter', __name__)

# Initialize the auth blueprint
subscription_blueprint = Blueprint('subscription', __name__)
auth_blueprint = Blueprint('auth', __name__)
review_blueprint = Blueprint('review', __name__)
report_blueprint = Blueprint('report', __name__)

# Import the views
from . import auth, newsletter, report, review, subscription
