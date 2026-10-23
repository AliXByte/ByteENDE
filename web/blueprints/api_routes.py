"""
ByteENDE · public REST API blueprint (/api/v1/*)
Stateless, Bearer-token authenticated (no cookies, no CSRF exposure). Each key
carries its own scopes and requests-per-minute limit, enforced by require_api_key.
"""
import functools
import io
import time

from flask import Blueprint, jsonify, request, send_file

from core import codecs as codec_core
from core import hashing as hash_core
from core import jwt_tool
from core import crypto_aes
from core import qr_tool
from web import auth

bp = Blueprint('api_routes', __name__, url_prefix='/api/v1')


def require_api_key(scope: str):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            authz = request.headers.get('Authorization', '')
            token = authz[7:] if authz.startswith('Bearer ') else request.headers.get('X-API-Key', '')
            key = auth.authenticate(token)
            if not key:
                return jsonify({'error': 'Invalid or missing API key'}), 401
            if not auth.check_scope(key, scope):
                return jsonify({'error': f'This key does not have the "{scope}" scope'}), 403
            if not auth.check_rate_limit(key):
                return jsonify({'error': 'Rate limit exceeded for this key'}), 429
            return fn(*a, **kw)
        return wrapper
    return deco


@bp.route('/codec', methods=['POST'])
@require_api_key('codec')
def api_codec():
    d = request.get_json(force=True, silent=True) or {}
    try:
        out = codec_core.run_codec(d.get('codec', ''), d.get('mode', ''), d.get('text', ''))
        return jsonify({'result': out})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/hash', methods=['POST'])
@require_api_key('hash')
def api_hash():
    d = request.get_json(force=True, silent=True) or {}
    text = d.get('text', '')
    algo = d.get('algo')
    try:
        if algo:
            return jsonify({'result': {algo: hash_core.hash_text(text, algo)}})
        return jsonify({'result': hash_core.hash_all(text)})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/jwt/decode', methods=['POST'])
@require_api_key('jwt')
def api_jwt_decode():
    d = request.get_json(force=True, silent=True) or {}
    try:
        return jsonify({'result': jwt_tool.decode(d.get('token', ''))})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/jwt/verify', methods=['POST'])
@require_api_key('jwt')
def api_jwt_verify():
    d = request.get_json(force=True, silent=True) or {}
    try:
        ok = jwt_tool.verify(d.get('token', ''), d.get('secret', ''))
        return jsonify({'result': {'valid': ok}})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/jwt/encode', methods=['POST'])
@require_api_key('jwt')
def api_jwt_encode():
    d = request.get_json(force=True, silent=True) or {}
    try:
        token = jwt_tool.encode(d.get('payload', {}), d.get('secret', ''), d.get('alg', 'HS256'))
        return jsonify({'result': token})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/aes/encrypt', methods=['POST'])
@require_api_key('aes')
def api_aes_encrypt():
    d = request.get_json(force=True, silent=True) or {}
    try:
        return jsonify({'result': crypto_aes.encrypt(d.get('text', ''), d.get('password', ''))})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/aes/decrypt', methods=['POST'])
@require_api_key('aes')
def api_aes_decrypt():
    d = request.get_json(force=True, silent=True) or {}
    try:
        return jsonify({'result': crypto_aes.decrypt(d.get('blob', ''), d.get('password', ''))})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/qr/generate', methods=['POST'])
@require_api_key('qr')
def api_qr_generate():
    d = request.get_json(force=True, silent=True) or {}
    try:
        png = qr_tool.generate(d.get('text', ''))
        return send_file(io.BytesIO(png), mimetype='image/png')
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/qr/read', methods=['POST'])
@require_api_key('qr')
def api_qr_read():
    f = request.files.get('image')
    if not f:
        return jsonify({'error': 'No image uploaded (multipart field "image")'}), 400
    try:
        return jsonify({'result': qr_tool.read(f.read())})
    except (ValueError, RuntimeError) as e:
        return jsonify({'error': str(e)}), 400


@bp.route('/ping')
def api_ping():
    return jsonify({'ok': True, 'service': 'ByteENDE', 'by': 'AliXByte', 'time': time.time()})
