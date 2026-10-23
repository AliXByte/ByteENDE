"""
ByteENDE · panel blueprint
The logged-in owner's dashboard, API-key management, and the session-authenticated
tool endpoints the dashboard's JS calls (/panel/*). These share the exact same
core/ logic as the public REST API, so results never drift between the two.
"""
import base64
import io
from datetime import datetime

from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for

from core import codecs as codec_core
from core import hashing as hash_core
from core import jwt_tool
from core import crypto_aes
from core import qr_tool
from web import auth
from web import network_acl
from web.blueprints.auth_routes import login_required

bp = Blueprint('panel_routes', __name__)


@bp.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html', active='dashboard')


@bp.route('/settings')
@login_required
def settings_page():
    return render_template('settings.html', active='settings')


@bp.route('/network')
@login_required
def network_page():
    settings = network_acl.get_settings()
    events = network_acl.recent_events(200)
    for e in events:
        e['time_str'] = datetime.fromtimestamp(e['ts']).strftime('%Y-%m-%d %H:%M:%S')
    return render_template(
        'network.html', active='network', net=settings,
        events=events, current_ip=request.remote_addr,
        dashboard_rules_text='\n'.join(settings['dashboard']['rules']),
        api_rules_text='\n'.join(settings['api']['rules']),
        mac_rules_text='\n'.join(settings['mac']['rules']),
        bad_lines=session.pop('network_bad_lines', None),
        net_ok=session.pop('network_ok', None),
    )


@bp.route('/network/update', methods=['POST'])
@login_required
def network_update():
    form = request.form.get('form', '')
    settings = network_acl.get_settings()
    bad = []

    if form == 'dashboard_acl':
        mode = request.form.get('mode', 'allow_all')
        rules, bad = network_acl.parse_ip_rules(request.form.get('rules', ''))
        settings['dashboard'] = {'mode': mode, 'rules': rules}
        ok_msg = 'Dashboard access rules saved.'
    elif form == 'api_acl':
        mode = request.form.get('mode', 'allow_all')
        rules, bad = network_acl.parse_ip_rules(request.form.get('rules', ''))
        settings['api'] = {'mode': mode, 'rules': rules}
        ok_msg = 'API access rules saved.'
    elif form == 'mac_acl':
        enabled = request.form.get('enabled') == 'on'
        rules, bad = network_acl.parse_mac_rules(request.form.get('rules', ''))
        settings['mac'] = {'enabled': enabled, 'rules': rules}
        ok_msg = 'Device (MAC) access rules saved.'
    elif form == 'bind_host':
        choice = request.form.get('bind_choice', '127.0.0.1')
        custom = request.form.get('bind_custom', '').strip()
        settings['bind_host'] = custom if choice == 'custom' and custom else choice
        ok_msg = 'Listen address saved — restart ByteENDE for it to take effect.'
    else:
        ok_msg = None

    if not bad and ok_msg:
        network_acl.save_settings(settings)
        session['network_ok'] = ok_msg
    elif bad:
        session['network_bad_lines'] = bad
    return redirect(url_for('panel_routes.network_page'))


@bp.route('/network/logs/clear', methods=['POST'])
@login_required
def network_logs_clear():
    network_acl.clear_log()
    return redirect(url_for('panel_routes.network_page'))


@bp.route('/keys')
@login_required
def keys_page():
    new_token = session.pop('new_token', None)
    return render_template('keys.html', keys=auth.list_keys(), scopes=auth.ALL_SCOPES, new_token=new_token, active='keys')


@bp.route('/keys/create', methods=['POST'])
@login_required
def keys_create():
    name = request.form.get('name', '').strip()
    scopes = request.form.getlist('scopes')
    rate = request.form.get('rate', 30)
    result = auth.create_key(name, scopes, rate)
    session['new_token'] = result['token']
    return redirect(url_for('panel_routes.keys_page'))


@bp.route('/keys/delete/<key_id>', methods=['POST'])
@login_required
def keys_delete(key_id):
    auth.delete_key(key_id)
    return redirect(url_for('panel_routes.keys_page'))


@bp.route('/keys/toggle/<key_id>', methods=['POST'])
@login_required
def keys_toggle(key_id):
    keys = {k['id']: k for k in auth.list_keys()}
    k = keys.get(key_id)
    if k:
        auth.set_key_enabled(key_id, not k['enabled'])
    return redirect(url_for('panel_routes.keys_page'))


# ---------------------------------------------------------------- panel-side tool endpoints
# (session-authenticated only - used by the dashboard's own JS, no API key needed)

@bp.route('/panel/codec', methods=['POST'])
@login_required
def panel_codec():
    d = request.get_json(force=True, silent=True) or {}
    try:
        out = codec_core.run_codec(d.get('codec', ''), d.get('mode', ''), d.get('text', ''))
        return jsonify({'ok': True, 'result': out})
    except ValueError as e:
        return jsonify({'ok': False, 'error': str(e)}), 400


@bp.route('/panel/hash', methods=['POST'])
@login_required
def panel_hash():
    d = request.get_json(force=True, silent=True) or {}
    text = d.get('text', '')
    return jsonify({'ok': True, 'result': hash_core.hash_all(text)})


@bp.route('/panel/jwt/decode', methods=['POST'])
@login_required
def panel_jwt_decode():
    d = request.get_json(force=True, silent=True) or {}
    try:
        return jsonify({'ok': True, 'result': jwt_tool.decode(d.get('token', ''))})
    except ValueError as e:
        return jsonify({'ok': False, 'error': str(e)}), 400


@bp.route('/panel/jwt/encode', methods=['POST'])
@login_required
def panel_jwt_encode():
    d = request.get_json(force=True, silent=True) or {}
    try:
        import json as _json
        payload = _json.loads(d.get('payload', '{}'))
        token = jwt_tool.encode(payload, d.get('secret', ''), d.get('alg', 'HS256'))
        return jsonify({'ok': True, 'result': token})
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Invalid payload JSON or secret: {e}'}), 400


@bp.route('/panel/aes/encrypt', methods=['POST'])
@login_required
def panel_aes_encrypt():
    d = request.get_json(force=True, silent=True) or {}
    try:
        out = crypto_aes.encrypt(d.get('text', ''), d.get('password', ''))
        return jsonify({'ok': True, 'result': out})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400


@bp.route('/panel/aes/decrypt', methods=['POST'])
@login_required
def panel_aes_decrypt():
    d = request.get_json(force=True, silent=True) or {}
    try:
        out = crypto_aes.decrypt(d.get('blob', ''), d.get('password', ''))
        return jsonify({'ok': True, 'result': out})
    except ValueError as e:
        return jsonify({'ok': False, 'error': str(e)}), 400


@bp.route('/panel/qr/generate', methods=['POST'])
@login_required
def panel_qr_generate():
    d = request.get_json(force=True, silent=True) or {}
    try:
        png = qr_tool.generate(d.get('text', ''))
        b64 = base64.b64encode(png).decode('ascii')
        return jsonify({'ok': True, 'result': 'data:image/png;base64,' + b64})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400


@bp.route('/panel/qr/read', methods=['POST'])
@login_required
def panel_qr_read():
    f = request.files.get('image')
    if not f:
        return jsonify({'ok': False, 'error': 'No image uploaded'}), 400
    try:
        out = qr_tool.read(f.read())
        return jsonify({'ok': True, 'result': out})
    except (ValueError, RuntimeError) as e:
        return jsonify({'ok': False, 'error': str(e)}), 400
