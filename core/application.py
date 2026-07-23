from datetime import timedelta

from flask import Flask, redirect, render_template, send_from_directory, url_for

from core.bootstrap import BASE_DIR, configure_application
from core.database import get_web_database
from core.templating import register_template_filters


def create_app():
    from auth.routes import auth_blueprint
    from auth.store import ensure_bootstrap_user
    from newsletters.routes import newsletter_blueprint
    from operations.routes import operations_blueprint
    from reports.routes import report_blueprint
    from reviews.routes import review_blueprint
    from subscriptions.profiles import ensure_sub_account_collection
    from subscriptions.routes import subscription_blueprint
    from subscriptions.scheduler import start_scheduler

    application = Flask(
        __name__,
        root_path=BASE_DIR,
        template_folder='templates',
        static_folder='static',
    )
    config = configure_application(BASE_DIR)
    application.config.update(config)
    application.config['TEMPLATES_AUTO_RELOAD'] = True
    application.permanent_session_lifetime = timedelta(hours=12)
    register_template_filters(application)
    ensure_sub_account_collection()
    ensure_bootstrap_user(config)

    @application.route('/')
    def home():
        return redirect(url_for('subscription.subscriptions'))

    @application.route('/image/<filename>')
    def serve_image(filename):
        return send_from_directory(f'{application.static_folder}/images', filename)

    @application.errorhandler(404)
    def page_not_found(error):
        return render_template('errors/404.html', image_filename='67.gif'), 404

    application.register_blueprint(newsletter_blueprint)
    application.register_blueprint(subscription_blueprint)
    application.register_blueprint(auth_blueprint)
    application.register_blueprint(review_blueprint)
    application.register_blueprint(report_blueprint)
    application.register_blueprint(operations_blueprint)
    start_scheduler(application, get_web_database)
    return application
