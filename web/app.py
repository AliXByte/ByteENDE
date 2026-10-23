"""
ByteENDE · Flask application factory

Designed & developed by AliXByte · https://github.com/AliXByte

One core, two faces: the web panel and the REST API both call the exact same
functions in core/, so a result never drifts between them.

Security posture (see README.md "Security" section for the full list):
  - Session cookies: HttpOnly, SameSite=Lax always; Secure when served over
    HTTPS (auto-detected, or forced with BYTEENDE_FORCE_HTTPS=1).
  - CSRF protection on every session-cookie POST form (the stateless, Bearer
    token-authenticated /api/v1/* routes are exempt - they carry no cookie).
  - Login lockout after repeated failed attempts (web/auth.py).
  - API tokens are never stored in plaintext - only their SHA-256 hash.
  - Security response headers (CSP, X-Frame-Options, nosniff, etc.) on every
    response via an after_request hook.
  - 5 MB request body cap, generous for a QR image upload, tight enough to
    blunt naive resource-exhaustion attempts.
  - Network access control (web/network_acl.py, Network page): optional
    IP/CIDR allow- or block-lists for the dashboard and the API separately,
    best-effort LAN-only MAC filtering, and an audit log of which IP did
    what. The loopback address always passes, so the owner can never be
    fully locked out of the machine ByteENDE runs on.
"""
import os
import sys

from flask import Flask, abort, g, jsonify, render_template, request, session

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from web import auth
from web import network_acl

APP_NAME = 'ByteENDE'
AUTHOR = 'AliXByte'
AUTHOR_URL = 'https://github.com/AliXByte'

# Session-cookie routes that change state and must carry a valid CSRF token.
# (/api/v1/* is Bearer-token authenticated and intentionally excluded.)
_CSRF_EXEMPT_PREFIXES = ('/api/v1/',)

# Always reachable from any IP, regardless of the dashboard IP/MAC policy:
# the login/setup screens (still gated behind the password itself) and the
# Network page (so the owner can never be permanently locked out of fixing
# their own rules). Static assets are needed to render any of those pages.
_NETWORK_ACL_EXEMPT_PATHS = {'/login', '/logout', '/setup'}
_NETWORK_ACL_EXEMPT_PREFIXES = ('/static/', '/network')


def create_app():
    app = Flask(__name__)
    app.secret_key = auth.get_session_secret()
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB

    # --- secure session cookie flags ---
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = os.environ.get('BYTEENDE_FORCE_HTTPS') == '1'
    app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 8  # 8 hours

    from web.blueprints.auth_routes import bp as auth_bp
    from web.blueprints.panel_routes import bp as panel_bp
    from web.blueprints.api_routes import bp as api_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(panel_bp)
    app.register_blueprint(api_bp)

    @app.context_processor
    def inject_globals():
        token = session.get('csrf_token')
        if not token:
            token = auth.new_csrf_token()
            session['csrf_token'] = token
        return {
            'user': session.get('user'),
            'csrf_token': token,
            'app_name': APP_NAME,
            'author': AUTHOR,
            'author_url': AUTHOR_URL,
        }

    @app.before_request
    def _enforce_network_acl():
        path = request.path
        if path in _NETWORK_ACL_EXEMPT_PATHS or path.startswith(_NETWORK_ACL_EXEMPT_PREFIXES):
            return None
        ip = request.remote_addr or 'unknown'
        section = 'api' if path.startswith('/api/v1/') else 'dashboard'
        settings = network_acl.get_settings()
        allowed, reason = network_acl.check_ip(ip, section, settings)
        if allowed:
            allowed, reason = network_acl.check_mac(ip, settings)
        if not allowed:
            g.net_blocked = True
            network_acl.log_event(ip, request.method, path, 403, 'blocked', session.get('user'), reason)
            if section == 'api':
                return jsonify({'error': 'Access denied by network policy'}), 403
            return render_template('blocked.html', reason=reason), 403
        return None

    @app.before_request
    def _enforce_csrf():
        if request.method != 'POST':
            return None
        if request.path.startswith(_CSRF_EXEMPT_PREFIXES):
            return None
        # Panel JSON tool endpoints (/panel/*) are same-origin fetch() calls
        # guarded by the session cookie's SameSite=Lax (a cross-site POST
        # cannot carry the cookie), and by login_required underneath; the
        # classic CSRF surface that matters most is the plain HTML <form>
        # posts below, so those are the ones required to present a token.
        if not request.path.startswith('/panel/'):
            submitted = request.form.get('csrf_token', '')
            expected = session.get('csrf_token', '')
            if not auth.csrf_valid(expected, submitted):
                abort(403)
        return None

    @app.after_request
    def _security_headers(resp):
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['Referrer-Policy'] = 'no-referrer'
        resp.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        resp.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        resp.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        if app.config['SESSION_COOKIE_SECURE']:
            resp.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
        return resp

    @app.after_request
    def _audit_log(resp):
        if not getattr(g, 'net_blocked', False) and not request.path.startswith('/static/'):
            network_acl.log_event(
                request.remote_addr or 'unknown', request.method, request.path,
                resp.status_code, 'ok' if resp.status_code < 400 else 'error', session.get('user'),
            )
        return resp

    return app


app = create_app()

if __name__ == '__main__':
    # Binds to localhost only by default - a safe default for a tool that holds
    # crypto keys and API tokens. BYTEENDE_HOST overrides the Network page's
    # saved "Listen address" (see run.py's docstring for the priority order).
    host = os.environ.get('BYTEENDE_HOST') or network_acl.get_settings().get('bind_host', '127.0.0.1')
    port = int(os.environ.get('BYTEENDE_PORT', '8800'))
    app.run(host=host, port=port, debug=False)
