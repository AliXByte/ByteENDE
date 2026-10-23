"""
ByteENDE · network access control

Lets the owner restrict which clients may reach the dashboard and/or the
REST API, by IP/CIDR and (best-effort, LAN-only) by MAC address, and records
an audit trail of what each client IP did.

Honesty note baked into the design: a MAC address is a layer-2 (local
network) identifier. A web server can never see the MAC address of a client
that is not on the same local network segment - not over the internet, and
not through any router, NAT or reverse proxy. MAC filtering here is
implemented as a best-effort check against the host's own ARP table (Linux
only, via /proc/net/arp) and only ever matches devices on the same LAN. It
is not a substitute for IP filtering when restricting remote access.
"""
import ipaddress
import json
import os
import platform
import re
import threading
import time
from collections import deque

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
NETWORK_FILE = os.path.join(DATA_DIR, 'network.json')
LOG_FILE = os.path.join(DATA_DIR, 'access_log.jsonl')

MAX_LOG_LINES = 5000        # hard cap on the persisted log file
TRIM_TO_LINES = 2000        # trimmed back down to this many on rotation
LOG_RING_SIZE = 500         # fast in-memory view for the Logs page

_lock = threading.Lock()
_log_ring = deque(maxlen=LOG_RING_SIZE)

DEFAULT_NETWORK = {
    'dashboard': {'mode': 'allow_all', 'rules': []},   # mode: allow_all | allowlist | blocklist
    'api': {'mode': 'allow_all', 'rules': []},
    'mac': {'enabled': False, 'rules': []},
    'bind_host': '127.0.0.1',
}

MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')


def _ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_json(path, default):
    if not os.path.exists(path):
        return json.loads(json.dumps(default))  # deep copy
    with open(path) as f:
        return json.load(f)


def _save_json(path, data):
    _ensure_data_dir()
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


# ---------- settings ----------

def get_settings() -> dict:
    data = _load_json(NETWORK_FILE, DEFAULT_NETWORK)
    # backfill any keys missing from an older saved file
    for k, v in DEFAULT_NETWORK.items():
        data.setdefault(k, json.loads(json.dumps(v)))
    return data


def save_settings(data: dict):
    _save_json(NETWORK_FILE, data)


def parse_ip_rules(text: str):
    """Parse one IP or CIDR per line. Returns (valid_list, bad_lines)."""
    valid, bad = [], []
    for raw in (text or '').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
            valid.append(str(net))
        except ValueError:
            bad.append(line)
    return valid, bad


def parse_mac_rules(text: str):
    """Parse one MAC address per line (accepts : or - separators). Returns (valid_list, bad_lines)."""
    valid, bad = [], []
    for raw in (text or '').splitlines():
        line = raw.strip().lower().replace('-', ':')
        if not line or line.startswith('#'):
            continue
        if MAC_RE.match(line):
            valid.append(line)
        else:
            bad.append(raw.strip())
    return valid, bad


def _ip_in_rules(ip: str, rules: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for rule in rules:
        try:
            if addr in ipaddress.ip_network(rule, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def check_ip(ip: str, section: str, settings: dict = None) -> tuple:
    """Returns (allowed: bool, reason: str). `section` is 'dashboard' or 'api'.
    The loopback address always passes, as a safety net so the owner can
    never be fully locked out of the machine ByteENDE runs on."""
    if is_loopback(ip):
        return True, 'loopback'
    settings = settings or get_settings()
    cfg = settings.get(section, {'mode': 'allow_all', 'rules': []})
    mode = cfg.get('mode', 'allow_all')
    rules = cfg.get('rules', [])
    if mode == 'allow_all':
        return True, 'allow_all'
    if mode == 'allowlist':
        return (True, 'allowlisted') if _ip_in_rules(ip, rules) else (False, 'not_on_allowlist')
    if mode == 'blocklist':
        return (False, 'blocklisted') if _ip_in_rules(ip, rules) else (True, 'not_on_blocklist')
    return True, 'unknown_mode'


# ---------- best-effort, LAN-only MAC resolution ----------

def resolve_mac(ip: str):
    """Best-effort local-network MAC lookup via the kernel ARP table. Only
    ever resolves a MAC for a device on the same LAN segment as this host,
    and only on Linux. Returns None (never raises) when it can't resolve -
    which is the normal, expected case for any remote/internet client."""
    if platform.system() != 'Linux':
        return None
    try:
        with open('/proc/net/arp') as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == ip:
                mac = parts[3].lower()
                if MAC_RE.match(mac) and mac != '00:00:00:00:00:00':
                    return mac
    except OSError:
        return None
    return None


def check_mac(ip: str, settings: dict = None) -> tuple:
    """Returns (allowed: bool, reason: str). Only called when MAC filtering
    is enabled. A client whose MAC can't be resolved (i.e. anyone not on the
    same local network as this host) is denied - that is the whole point of
    MAC filtering, and is called out clearly in the Network page's UI."""
    if is_loopback(ip):
        return True, 'loopback'
    settings = settings or get_settings()
    mac_cfg = settings.get('mac', {'enabled': False, 'rules': []})
    if not mac_cfg.get('enabled'):
        return True, 'mac_filter_disabled'
    mac = resolve_mac(ip)
    if not mac:
        return False, 'mac_unresolvable'
    if mac in mac_cfg.get('rules', []):
        return True, 'mac_allowlisted'
    return False, 'mac_not_allowlisted'


# ---------- audit log ----------

def _trim_log_file_if_needed():
    try:
        if not os.path.exists(LOG_FILE):
            return
        with open(LOG_FILE) as f:
            lines = f.readlines()
        if len(lines) > MAX_LOG_LINES:
            with open(LOG_FILE, 'w') as f:
                f.writelines(lines[-TRIM_TO_LINES:])
    except OSError:
        pass


def log_event(ip: str, method: str, path: str, status: int, result: str, user=None, reason=None):
    entry = {
        'ts': time.time(), 'ip': ip, 'method': method, 'path': path,
        'status': status, 'result': result, 'user': user, 'reason': reason,
    }
    with _lock:
        _log_ring.append(entry)
        try:
            _ensure_data_dir()
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            _trim_log_file_if_needed()
        except OSError:
            pass


def recent_events(limit: int = 200) -> list:
    """Most recent first. Reads the in-memory ring buffer (fast path); if the
    process just restarted and the ring is thinner than the file, backfills
    from disk."""
    with _lock:
        events = list(_log_ring)
    if len(events) < limit and os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE) as f:
                lines = f.readlines()[-limit:]
            events = [json.loads(l) for l in lines if l.strip()]
        except (OSError, json.JSONDecodeError):
            pass
    return list(reversed(events[-limit:]))


def clear_log():
    with _lock:
        _log_ring.clear()
        try:
            if os.path.exists(LOG_FILE):
                os.remove(LOG_FILE)
        except OSError:
            pass
