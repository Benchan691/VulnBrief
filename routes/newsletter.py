import os
import shutil
from functools import wraps
from . import newsletter_blueprint
from flask import render_template, request, jsonify, session, redirect, url_for, current_app


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


@newsletter_blueprint.route('/en')
def get_new_en():
    return render_template('news_en.html')

@newsletter_blueprint.route('/zh')
def get_news_zh():
    return render_template('news_zh.html')

@newsletter_blueprint.route('/cn')
def get_news_cn():
    return render_template('news_cn.html')


@newsletter_blueprint.route('/set-news', methods=['POST'])
@login_required
def set_news():
    data = request.get_json()
    lang = (data.get('lang') or '').lower()
    filepath = (data.get('path') or '').strip('/')

    if lang not in ('en', 'cn', 'zh'):
        return jsonify({'error': 'Invalid language'}), 400

    base = os.path.realpath(current_app.config['NEWSLETTER_ROOT'])
    source = os.path.realpath(os.path.join(base, filepath))

    if not source.startswith(base + os.sep) and source != base:
        return jsonify({'error': 'Invalid path'}), 403
    if not os.path.isfile(source):
        return jsonify({'error': 'File not found'}), 404

    dest = os.path.join(current_app.root_path, 'templates', f'news_{lang}.html')
    shutil.copy2(source, dest)
    return jsonify({'success': True})

