import os
from datetime import timedelta, datetime
from flask import Flask, render_template, send_from_directory, request, abort
from routes.newsletter import newsletter_blueprint
from routes.subscription import subscription_blueprint
from routes.auth import auth_blueprint
from routes.review import review_blueprint
from routes.report import report_blueprint
from bootstrap import BASE_DIR, configure_application


def _fmt_size(n):
    if n < 1024:
        return f'{n} B'
    if n < 1024 * 1024:
        return f'{n / 1024:.1f} KB'
    return f'{n / (1024 * 1024):.1f} MB'


def _has_html(path):
    """Recursively check if a directory contains at least one HTML file."""
    try:
        for entry in os.scandir(path):
            if entry.is_file() and entry.name.lower().endswith('.html'):
                return True
            if entry.is_dir() and _has_html(entry.path):
                return True
    except PermissionError:
        pass
    return False


def create_app():
    application = Flask(__name__)
    application.config.update(configure_application(BASE_DIR))
    application.config['TEMPLATES_AUTO_RELOAD'] = True
    application.permanent_session_lifetime = timedelta(hours=12)

    @application.route('/')
    def browse():
        rel_path = request.args.get('path', '').strip('/')
        newsletter_root = application.config['NEWSLETTER_ROOT']
        base = os.path.realpath(newsletter_root)
        target = os.path.realpath(os.path.join(base, rel_path)) if rel_path else base

        if not target.startswith(base):
            abort(403)
        if not os.path.isdir(target):
            abort(404)

        entries = []
        try:
            for entry in sorted(os.scandir(target), key=lambda e: (not e.is_dir(), e.name.lower())):
                if entry.is_dir() and not _has_html(entry.path):
                    continue
                stat = entry.stat()
                entry_rel = (rel_path + '/' + entry.name).lstrip('/') if rel_path else entry.name
                entries.append({
                    'name': entry.name,
                    'is_dir': entry.is_dir(),
                    'is_html': entry.name.lower().endswith('.html'),
                    'size': _fmt_size(stat.st_size) if not entry.is_dir() else None,
                    'mtime': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                    'path': entry_rel,
                })
        except PermissionError:
            abort(403)

        parts = [p for p in rel_path.split('/') if p]
        breadcrumbs = [{'name': p, 'path': '/'.join(parts[:i + 1])} for i, p in enumerate(parts)]
        parent_path = '/'.join(parts[:-1]) if parts else None

        return render_template(
            'browse.html',
            entries=entries,
            rel_path=rel_path,
            breadcrumbs=breadcrumbs,
            parent_path=parent_path,
        )

    @application.route('/view/<path:filepath>')
    def view_file(filepath):
        newsletter_root = application.config['NEWSLETTER_ROOT']
        base = os.path.realpath(newsletter_root)
        target = os.path.realpath(os.path.join(base, filepath))
        if not target.startswith(base):
            abort(403)
        if not os.path.isfile(target):
            abort(404)
        return send_from_directory(os.path.dirname(target), os.path.basename(target))

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
