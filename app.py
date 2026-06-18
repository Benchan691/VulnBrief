from datetime import timedelta
from flask import Flask, render_template, send_from_directory, redirect, url_for
from routes.newsletter import newsletter_blueprint
from routes.subscription import subscription_blueprint
from routes.auth import auth_blueprint
from routes.review import review_blueprint
from routes.report import report_blueprint
from bootstrap import BASE_DIR, configure_application


def create_app():
    application = Flask(__name__)
    application.config.update(configure_application(BASE_DIR))
    application.config['TEMPLATES_AUTO_RELOAD'] = True
    application.permanent_session_lifetime = timedelta(hours=12)

    @application.route('/')
    def home():
        return redirect(url_for('subscription.subscriptions'))

    @application.route('/image/<filename>')
    def serve_image(filename):
        return send_from_directory('static', filename)

    @application.errorhandler(404)
    def page_not_found(error):
        image_filename = '67.gif'
        return render_template('404.html', image_filename=image_filename), 404

    application.register_blueprint(newsletter_blueprint)
    application.register_blueprint(subscription_blueprint)
    application.register_blueprint(auth_blueprint)
    application.register_blueprint(review_blueprint)
    application.register_blueprint(report_blueprint)
    return application


app = create_app()

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=False, host='0.0.0.0', port=6767)
