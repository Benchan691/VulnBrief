import os
import shutil
from . import newsletter_blueprint
from flask import Response, render_template, request, jsonify, current_app
from mongo import get_vulnerabilities_database
from newsletter_store import render_newsletter
from pymongo.errors import PyMongoError
from review_data import resolve_vulnerability_document
from .common import login_required


@newsletter_blueprint.route('/<lang>')
def get_news(lang):
    if lang not in {'en', 'zh', 'cn'}:
        return jsonify({'error': 'Not found'}), 404
    return render_template(f'news_{lang}.html')


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


@newsletter_blueprint.route('/generated-newsletters/<source_collection>/<path:selection_id>/preview')
@login_required
def generated_newsletter_preview(source_collection, selection_id):
    try:
        document = resolve_vulnerability_document(
            get_vulnerabilities_database(),
            source_collection,
            selection_id,
        )
        if document is None:
            return jsonify({'error': 'Newsletter source document not found.'}), 404
        rendered, _ = render_newsletter(document, source_collection)
        return Response(rendered, content_type='text/html; charset=utf-8')
    except PyMongoError:
        return jsonify({'error': 'Unable to render generated newsletter.'}), 503
