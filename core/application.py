from datetime import timedelta

from flask import Flask, make_response, redirect, render_template, request, send_from_directory, url_for

from core.bootstrap import BASE_DIR, configure_application
from core.database import get_web_database
from core.i18n import COOKIE_NAME, normalize_locale
from core.templating import register_template_filters


def create_app():
    from auth.routes import auth_blueprint
    from auth.store import (
        ensure_admin_data_ownership,
        ensure_bootstrap_user,
        ensure_legacy_subscription_users,
    )
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
    ensure_legacy_subscription_users()
    ensure_admin_data_ownership()

    @application.route('/')
    def home():
        return redirect(url_for('subscription.subscriptions'))

    @application.route('/locale/<code>')
    def set_locale(code):
        locale = normalize_locale(code)
        next_url = request.args.get('next') or request.referrer or url_for('subscription.subscriptions')
        if not next_url.startswith('/') or next_url.startswith('//'):
            next_url = url_for('subscription.subscriptions')
        response = make_response(redirect(next_url))
        response.set_cookie(COOKIE_NAME, locale, max_age=365 * 24 * 60 * 60, samesite='Lax')
        return response

    @application.route('/image/<filename>')
    def serve_image(filename):
        return send_from_directory(f'{application.static_folder}/images', filename)

    @application.errorhandler(404)
    def page_not_found(error):
        return render_template('errors/404.html', image_filename='67.gif'), 404

    @application.errorhandler(403)
    def access_denied(error):
        if request.path.startswith('/api/'):
            return {'error': 'Access denied.'}, 403
        return render_template('errors/403.html'), 403

    application.register_blueprint(newsletter_blueprint)
    application.register_blueprint(subscription_blueprint)
    application.register_blueprint(auth_blueprint)
    application.register_blueprint(review_blueprint)
    application.register_blueprint(report_blueprint)
    application.register_blueprint(operations_blueprint)
    start_scheduler(application, get_web_database)
    return application
