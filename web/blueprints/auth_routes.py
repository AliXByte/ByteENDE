"""
ByteENDE · auth blueprint
First-run owner setup, login/logout, and the account (password change) page.
All session-cookie state-changing endpoints here are covered by the app-wide
CSRF check in web/app.py, and failed logins are tracked by web.auth for lockout.
"""
import functools

from flask import Blueprint, redirect, render_template, request, session, url_for

from web import auth

bp = Blueprint('auth_routes', __name__)


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not session.get('user'):
            return redirect(url_for('auth_routes.login'))
        return fn(*a, **kw)
    return wrapper


@bp.route('/setup', methods=['GET', 'POST'])
def setup():
    if auth.owner_exists():
        return redirect(url_for('auth_routes.login'))
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '')
        p2 = request.form.get('password2', '')
        if not (3 <= len(u) <= 24):
            error = 'Username must be 3-24 characters.'
        elif len(p) < 8:
            error = 'Password must be at least 8 characters.'
        elif p != p2:
            error = 'Passwords do not match.'
        else:
            auth.set_owner_password(u, p)
            session.clear()
            session['user'] = u
            return redirect(url_for('panel_routes.dashboard'))
    return render_template('setup.html', error=error)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if not auth.owner_exists():
        return redirect(url_for('auth_routes.setup'))
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '')
        remaining = auth.is_locked_out(u)
        if remaining:
            error = f'Too many failed attempts. Try again in {int(remaining // 60) + 1} minute(s).'
        elif auth.verify_owner(u, p):
            session.clear()
            session['user'] = u
            return redirect(url_for('panel_routes.dashboard'))
        else:
            error = 'Wrong username or password.'
    return render_template('login.html', error=error)


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth_routes.login'))


@bp.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    error = ok = None
    name_error = name_ok = None
    if request.method == 'POST':
        form = request.form.get('form', 'password')
        if form == 'username':
            new_username = request.form.get('new_username', '')
            cur_pw = request.form.get('current_for_username', '')
            result = auth.change_owner_username(new_username, cur_pw)
            if result:
                session['user'] = result
                name_ok = f'Username updated to "{result}".'
            elif not (3 <= len(new_username.strip()) <= 24):
                name_error = 'Username must be 3-24 characters.'
            else:
                name_error = 'Current password is wrong.'
        else:
            cur = request.form.get('current', '')
            new = request.form.get('new', '')
            if len(new) < 8:
                error = 'New password must be at least 8 characters.'
            elif auth.change_owner_password(cur, new):
                ok = 'Password updated.'
            else:
                error = 'Current password is wrong.'
    return render_template(
        'account.html', error=error, ok=ok, name_error=name_error, name_ok=name_ok, active='account'
    )
