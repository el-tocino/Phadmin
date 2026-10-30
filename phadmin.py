import os
import json
import secrets
import logging
import functools
import re
import ssl
import time
import hashlib
import threading
import http.client
import sys
import atexit
import signal
import tempfile
import subprocess
from datetime import timedelta
from functools import wraps
from flask import Flask, render_template_string, request, jsonify, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from phue import Bridge, PhueRegistrationException

# ==========================================
# 1. Configuration & Setup
# ==========================================
CONFIG_FILE = 'config.json'
DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "port": 8215,
    "active_bridge": None,
    "bridges": {},   # {"ip_address": "username"}
    "secret_key": None,
    "users": {},     # {"username": {"password_hash":..., "role": "admin"|"member", "rooms": [group_id,...]}}
    "v2_pins": {}    # {"bridge_ip": "sha256 of the bridge's TLS certificate", set on first use}
}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        return json.loads(json.dumps(DEFAULT_CONFIG))
    with open(CONFIG_FILE, 'r') as f:
        cfg = json.load(f)
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    return cfg


def save_config(config_data):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_data, f, indent=4)


config = load_config()

if not config.get('secret_key'):
    config['secret_key'] = secrets.token_hex(32)
    save_config(config)

if not config.get('users'):
    _pw = secrets.token_urlsafe(9)
    config['users'] = {'admin': {'password_hash': generate_password_hash(_pw), 'role': 'admin', 'rooms': []}}
    save_config(config)
    print("=" * 60)
    print("[*] No users existed yet - created a default admin account:")
    print("      username: admin")
    print(f"      password: {_pw}")
    print("    Sign in and change this from the Account page.")
    print("=" * 60)

app = Flask(__name__)
app.secret_key = config['secret_key']
app.permanent_session_lifetime = timedelta(days=30)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
logging.basicConfig(level=logging.INFO)

# Cache of connected bridge objects
connected_bridges = {}


def get_bridge():
    ip = config.get('active_bridge')
    if not ip:
        return None
    if ip not in connected_bridges:
        try:
            username = config['bridges'].get(ip)
            b = Bridge(ip, username=username) if username else Bridge(ip)
            b.connect()
            connected_bridges[ip] = b
        except Exception as e:
            logging.error(f"Failed to connect to bridge {ip}: {e}")
            return None
    return connected_bridges[ip]


def hue_ok(resp):
    """The Hue API returns HTTP 200 with an error list on failure; surface those."""
    if isinstance(resp, list):
        for item in resp:
            if isinstance(item, dict) and 'error' in item:
                raise RuntimeError(item['error'].get('description', 'Hue bridge error'))
    return resp


# ==========================================
# 2. Auth & Permissions
# ==========================================
class Forbidden(Exception):
    pass


def current_user():
    """Returns {'username', 'role', 'rooms'} for the signed-in user, or None. Never exposes the password hash."""
    uname = session.get('user')
    if not uname or uname not in config['users']:
        return None
    u = config['users'][uname]
    return {'username': uname, 'role': u.get('role', 'member'), 'rooms': list(u.get('rooms', []))}


def require_admin(user):
    if user['role'] != 'admin':
        raise Forbidden('Admins only')


def user_light_ids(user, b):
    """String IDs of lights that live in one of this user's rooms."""
    rooms = set(user.get('rooms', []))
    ids = set()
    for gid, g in b.get_group().items():
        if gid in rooms:
            ids.update(g.get('lights', []))
    return ids


def scope_data(user, data):
    """Filter lights/groups down to a non-admin's assigned rooms."""
    if user['role'] == 'admin':
        return data
    rooms = set(user.get('rooms', []))
    groups = {gid: g for gid, g in data['groups'].items() if gid in rooms}
    light_ids = {lid for g in groups.values() for lid in g.get('lights', [])}
    lights = {lid: l for lid, l in data['lights'].items() if lid in light_ids}
    return {**data, 'groups': groups, 'lights': lights}


@app.before_request
def _auth_gate():
    if request.path in ('/login', '/logout') or request.path.startswith('/static'):
        return
    if not current_user():
        if request.path.startswith('/api/'):
            return jsonify(success=False, error='Not logged in'), 401
        nxt = request.full_path.rstrip('?') if request.query_string else request.path
        return redirect('/login?next=' + nxt)


def api_endpoint(fn):
    """For endpoints that need a logged-in user AND an active bridge. fn(user, bridge, ...)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        b = get_bridge()
        if not b:
            return jsonify(success=False, error='No active bridge connected'), 400
        try:
            result = fn(user, b, *args, **kwargs)
            return jsonify(success=True, **(result or {}))
        except Forbidden as e:
            return jsonify(success=False, error=str(e) or 'Not permitted'), 403
        except ValueError as e:  # bad user input: report it, no stack trace
            return jsonify(success=False, error=str(e)), 400
        except Exception as e:
            logging.exception("API error")
            return jsonify(success=False, error=str(e)), 500
    return wrapper


def admin_api(fn):
    """For user-management endpoints: admin-only, no bridge needed. fn(user, ...)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user['role'] != 'admin':
            return jsonify(success=False, error='Admins only'), 403
        try:
            result = fn(user, *args, **kwargs)
            return jsonify(success=True, **(result or {}))
        except Exception as e:
            return jsonify(success=False, error=str(e)), 400
    return wrapper


def auth_api(fn):
    """For endpoints any logged-in user may call on themselves. fn(user, ...)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        try:
            result = fn(user, *args, **kwargs)
            return jsonify(success=True, **(result or {}))
        except Exception as e:
            return jsonify(success=False, error=str(e)), 400
    return wrapper


def body():
    return request.get_json(silent=True) or request.form.to_dict()


# ==========================================
# 3. Utility Functions (Color Math + Sensors)
# ==========================================
def hex_to_xy(hex_color):
    """Converts HTML hex color to Philips Hue CIE xy color space."""
    hex_color = hex_color.lstrip('#')
    if len(hex_color) != 6:
        return [0.5, 0.5]
    r, g, b = tuple(int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    r, g, b = r / 255.0, g / 255.0, b / 255.0
    r = ((r + 0.055) / 1.055) ** 2.4 if r > 0.04045 else r / 12.92
    g = ((g + 0.055) / 1.055) ** 2.4 if g > 0.04045 else g / 12.92
    b = ((b + 0.055) / 1.055) ** 2.4 if b > 0.04045 else b / 12.92

    X = r * 0.664511 + g * 0.154324 + b * 0.162028
    Y = r * 0.283881 + g * 0.668433 + b * 0.047685
    Z = r * 0.000088 + g * 0.072310 + b * 0.986039

    if (X + Y + Z) == 0:
        return [0.0, 0.0]
    return [X / (X + Y + Z), Y / (X + Y + Z)]


def xy_to_hex(x, y, bri=254):
    """Converts Philips Hue CIE xy values back to an HTML hex color."""
    z = 1.0 - x - y
    Y = bri / 254.0
    if y == 0:
        X = 0
        Z = 0
    else:
        X = (Y / y) * x
        Z = (Y / y) * z

    r = X * 3.2406 - Y * 1.5372 - Z * 0.4986
    g = -X * 0.9689 + Y * 1.8758 + Z * 0.0415
    b = X * 0.0557 - Y * 0.2040 + Z * 1.0570

    r = r * 12.92 if r <= 0.0031308 else 1.055 * pow(r, (1.0 / 2.4)) - 0.055
    g = g * 12.92 if g <= 0.0031308 else 1.055 * pow(g, (1.0 / 2.4)) - 0.055
    b = b * 12.92 if b <= 0.0031308 else 1.055 * pow(b, (1.0 / 2.4)) - 0.055

    m = max(r, g, b, 1e-6)
    if m > 1:
        r, g, b = r / m, g / m, b / m
    r = int(max(0, min(1, r)) * 255)
    g = int(max(0, min(1, g)) * 255)
    b = int(max(0, min(1, b)) * 255)
    return f"#{r:02x}{g:02x}{b:02x}"


app.jinja_env.globals['xy_to_hex'] = xy_to_hex  # available inside template macros/fragments


def decode_button(stype, ev):
    """Human-readable name for a Hue switch buttonevent code."""
    if ev is None:
        return None
    if stype == 'ZGPSwitch':  # Hue Tap
        return {34: 'Button 1', 16: 'Button 2', 17: 'Button 3', 18: 'Button 4'}.get(ev, f'Event {ev}')
    btn, act = ev // 1000, ev % 1000  # ZLLSwitch: dimmer switch / smart button
    name = {1: 'On', 2: 'Dim up', 3: 'Dim down', 4: 'Off'}.get(btn, f'Button {btn}')
    action = {0: 'pressed', 1: 'held', 2: 'released', 3: 'released after hold'}.get(act, f'event {act}')
    return f"{name} {action}"


ON_OFF_TYPES = ('ZLLPresence', 'ZLLTemperature', 'ZLLLightLevel', 'CLIPPresence',
                'CLIPTemperature', 'CLIPLightLevel', 'Daylight')


def summarize_sensors(raw):
    """
    Group the bridge's raw sensor list into physical devices.
    A Hue motion sensor is exposed as three sensors (presence, temperature,
    light level) that share the MAC prefix of their uniqueid.
    """
    devices = {}
    for sid, s in raw.items():
        stype = s.get('type', '')
        state, cfg = s.get('state', {}), s.get('config', {})
        uid = s.get('uniqueid') or ''
        key = uid.split('-')[0] if uid else f'virtual-{sid}'
        d = devices.setdefault(key, {
            'key': key, 'name': s.get('name'), 'model': s.get('productname') or s.get('modelid') or stype,
            'manufacturer': s.get('manufacturername'), 'kind': 'generic', 'battery': None,
            'reachable': None, 'lastupdated': None, 'readings': []})

        if cfg.get('battery') is not None:
            d['battery'] = cfg['battery']
        if cfg.get('reachable') is not None:
            d['reachable'] = cfg['reachable']
        lu = state.get('lastupdated')
        if lu and lu != 'none' and (not d['lastupdated'] or lu > d['lastupdated']):
            d['lastupdated'] = lu

        r = {'id': sid, 'type': stype, 'enabled': cfg.get('on') if stype in ON_OFF_TYPES else None,
             'settings': {}}

        if stype in ('ZLLPresence', 'CLIPPresence'):
            d['kind'] = 'presence'
            d['name'] = s.get('name') if 'sensor' in (s.get('name') or '').lower() else d['name']
            r.update(label='Motion', kind='presence', active=bool(state.get('presence')),
                     value='Motion detected' if state.get('presence') else 'Clear')
            if 'sensitivity' in cfg:
                r['settings']['sensitivity'] = {'value': cfg['sensitivity'], 'max': cfg.get('sensitivitymax', 2)}
            if 'ledindication' in cfg:
                r['settings']['ledindication'] = bool(cfg['ledindication'])
        elif stype in ('ZLLTemperature', 'CLIPTemperature'):
            t = state.get('temperature')
            c = None if t is None else round(t / 100.0, 1)
            r.update(label='Temperature', kind='temperature', celsius=c)
            if d['kind'] == 'generic':
                d['kind'] = 'temperature'
        elif stype in ('ZLLLightLevel', 'CLIPLightLevel'):
            ll = state.get('lightlevel')
            lux = None if ll is None else round(10 ** ((ll - 1) / 10000.0), 1)
            r.update(label='Light level', kind='light', lux=lux,
                     daylight=state.get('daylight'), dark=state.get('dark'))
            if d['kind'] == 'generic':
                d['kind'] = 'light'
        elif stype in ('ZLLSwitch', 'ZGPSwitch'):
            d['kind'] = 'switch'
            r.update(label='Last button', kind='switch',
                     value=decode_button(stype, state.get('buttonevent')) or 'No presses yet')
        elif stype == 'Daylight':
            d['kind'] = 'daylight'
            r.update(label='Daylight', kind='daylight', active=bool(state.get('daylight')),
                     value='Daytime' if state.get('daylight') else 'Night')
        else:
            extra = {k: v for k, v in state.items() if k != 'lastupdated'}
            r.update(label=stype or 'Sensor', kind='generic',
                     value=', '.join(f'{k}: {v}' for k, v in extra.items()) or '-')
        d['readings'].append(r)

    return sort_devices(list(devices.values()))


SENSOR_ORDER = {'presence': 0, 'contact': 1, 'switch': 2, 'daylight': 3, 'temperature': 4, 'light': 5, 'generic': 6}


def sort_devices(devices):
    return sorted(devices, key=lambda d: (SENSOR_ORDER.get(d['kind'], 9), d['name'] or ''))


# ==========================================
# 3b. Hue v2 add-on: contact sensors
# ==========================================
# phue only speaks the v1 API, and the bridge doesn't expose the Hue Secure contact
# sensor there. This is a small client for the v2 (CLIP v2) API, used only for that.
# A v1 username works as the v2 "hue-application-key", so nothing needs re-pairing.
V2_PORT = 443
V2_TTL = 3             # seconds to reuse a snapshot (several browsers may be polling)
V2_DEVICE_TTL = 60     # seconds to reuse a device's name/model
V2_RETRY_AFTER = 600   # seconds before retrying a bridge that has no v2 API


class V2Error(RuntimeError):
    pass


class V2Unsupported(V2Error):
    """No v2 API here (old bridge or firmware). Not worth showing the user an error."""


_v2_lock = threading.RLock()
_v2_state = {}  # ip -> {'unsupported_until': ts, 'contacts': (ts, devices), 'devices': {rid: (ts, info)}}


def v2_request(ip, key, method, path, body=None, timeout=5):
    """One v2 call; returns the response's "data" list.
    The bridge's certificate comes from a private CA, so normal verification can't work.
    Instead its fingerprint is pinned the first time we connect (trust on first use)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(ip, V2_PORT, timeout=timeout, context=ctx)
    try:
        try:
            conn.connect()
        except OSError as e:  # refused, timed out, or not speaking TLS
            raise V2Unsupported(f'Hue v2 API not reachable ({e})')
        fingerprint = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        pins = config.setdefault('v2_pins', {})
        if ip not in pins:
            pins[ip] = fingerprint
            save_config(config)
        elif pins[ip] != fingerprint:
            raise V2Error("The bridge's security certificate changed since it was first trusted. If you reset "
                          "the bridge, delete its entry under 'v2_pins' in config.json and restart.")
        headers = {'hue-application-key': key}
        payload = None
        if body is not None:
            payload = json.dumps(body)
            headers['Content-Type'] = 'application/json'
        conn.request(method, f'/clip/v2/resource/{path}', payload, headers)
        res = conn.getresponse()
        raw = res.read()
    finally:
        conn.close()
    if res.status == 404:
        raise V2Unsupported('Hue v2 API not available on this bridge')
    if res.status in (401, 403):
        raise V2Error('The bridge rejected the application key for its v2 API')
    try:
        doc = json.loads(raw or b'{}')
    except ValueError:
        raise V2Error(f'Unexpected response from the bridge (HTTP {res.status})')
    errors = doc.get('errors') or []
    if res.status >= 400 or errors:
        raise V2Error('; '.join(e.get('description', 'error') for e in errors) or f'Bridge returned HTTP {res.status}')
    return doc.get('data') or []


def _by_owner(items):
    return {(i.get('owner') or {}).get('rid'): i for i in items if (i.get('owner') or {}).get('rid')}


def _iso(ts):
    """v2 stamps look like 2023-09-19T10:23:41.000Z; the UI expects v1's 2023-09-19T10:23:41 (UTC)."""
    return ts.rstrip('Z').split('.')[0] if isinstance(ts, str) and ts else None


def _device_info(ip, key, rid, st):
    now = time.time()
    hit = st.setdefault('devices', {}).get(rid)
    if hit and now - hit[0] < V2_DEVICE_TTL:
        return hit[1]
    info = (v2_request(ip, key, 'GET', f'device/{rid}') or [{}])[0]
    st['devices'][rid] = (now, info)
    return info


def _build_contact_devices(ip, key, st):
    contacts = v2_request(ip, key, 'GET', 'contact')
    if not contacts:
        return []
    tampers = _by_owner(v2_request(ip, key, 'GET', 'tamper'))
    power = _by_owner(v2_request(ip, key, 'GET', 'device_power'))
    link = _by_owner(v2_request(ip, key, 'GET', 'zigbee_connectivity'))

    out = []
    for c in contacts:
        owner = (c.get('owner') or {}).get('rid')
        dev = _device_info(ip, key, owner, st) if owner else {}
        meta, prod = dev.get('metadata') or {}, dev.get('product_data') or {}

        report = c.get('contact_report') or {}
        state = report.get('state')  # "contact" = closed (magnet near), "no_contact" = open
        is_open = state == 'no_contact'
        stamps = [report.get('changed')]
        readings = [{'id': c.get('id'), 'type': 'contact', 'v2': 'contact', 'enabled': c.get('enabled'),
                     'settings': {}, 'label': 'Door / window', 'kind': 'contact', 'active': is_open,
                     'value': 'Open' if is_open else ('Closed' if state == 'contact' else 'Unknown')}]

        tamper = tampers.get(owner)
        if tamper:
            reports = tamper.get('tamper_reports') or []
            tampered = any(r.get('state') == 'tampered' for r in reports)
            stamps += [r.get('changed') for r in reports]
            readings.append({'id': tamper.get('id'), 'type': 'tamper', 'v2': None, 'enabled': None, 'settings': {},
                             'label': 'Tamper', 'kind': 'tamper', 'active': tampered,
                             'value': 'Tampered' if tampered else 'OK'})

        level = (power.get(owner) or {}).get('power_state', {}).get('battery_level')
        battery = int(round(level)) if isinstance(level, (int, float)) and 0 <= level <= 100 else None
        status = (link.get(owner) or {}).get('status')

        out.append({'key': owner or c.get('id'), 'name': meta.get('name') or 'Contact sensor',
                    'model': prod.get('product_name') or 'Hue secure contact sensor',
                    'manufacturer': prod.get('manufacturer_name'), 'kind': 'contact', 'battery': battery,
                    'reachable': None if not status else status == 'connected',
                    'lastupdated': _iso(max((x for x in stamps if x), default=None)), 'readings': readings})
    return out


def contact_devices(b):
    """-> (devices, notice). Never raises: contact sensors must not break the v1 sensor list.
    A notice is only returned for problems worth showing (not for bridges that simply lack v2)."""
    ip, key = b.ip, b.username
    with _v2_lock:
        st = _v2_state.setdefault(ip, {})
        now = time.time()
        if st.get('unsupported_until', 0) > now:
            return [], None
        hit = st.get('contacts')
        if hit and now - hit[0] < V2_TTL:
            return hit[1], None
        try:
            devices = _build_contact_devices(ip, key, st)
        except V2Unsupported:
            st['unsupported_until'] = now + V2_RETRY_AFTER
            return [], None
        except V2Error as e:
            return [], f'Contact sensors unavailable: {e}'
        except Exception as e:
            logging.warning(f'Contact sensor lookup failed: {e}')
            return [], f'Contact sensors unavailable: {e}'
        st['contacts'] = (now, devices)
        return devices, None


# ==========================================
# 4. HTML / JS Templates (Embedded SPA)
# ==========================================
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in · Hue Admin</title>
{% raw %}
<style>
:root{--bg:#f4f5f9;--surface:#fff;--border:#e2e5ee;--text:#1b1d29;--muted:#6b7086;--primary:#6d5dfc;--primary-fg:#fff;--danger:#e5484d;}
@media (prefers-color-scheme: dark){:root{--bg:#0f1117;--surface:#181b25;--border:#2a2f40;--text:#eceef6;--muted:#8b91a8;--primary:#8b7dff;--primary-fg:#0f1117;}}
*{box-sizing:border-box;}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;}
.card{width:320px;background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px;box-shadow:0 8px 24px rgba(20,20,50,.12);}
.brand{display:flex;align-items:center;gap:8px;font-weight:700;margin-bottom:4px;}
.brand i{width:22px;height:22px;border-radius:7px;background:linear-gradient(135deg,#ffb14a,#ff5f8d,#6d5dfc);display:inline-block;}
p{color:var(--muted);font-size:.85rem;margin:0 0 20px;}
input{width:100%;background:transparent;border:1px solid var(--border);color:var(--text);border-radius:10px;padding:10px 12px;font:inherit;margin-bottom:12px;}
button{width:100%;background:var(--primary);color:var(--primary-fg);border:0;border-radius:10px;padding:11px;font:inherit;font-weight:600;cursor:pointer;}
.err{background:color-mix(in srgb, var(--danger) 14%, transparent);color:var(--danger);padding:10px 12px;border-radius:10px;font-size:.85rem;margin-bottom:14px;}
</style>
{% endraw %}
</head>
<body>
<div class="card">
  <div class="brand"><i></i> Hue Admin</div>
  <p>Sign in to control the lights.</p>
  {% if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="POST">
    <input type="hidden" name="next" value="{{ next }}">
    <input type="text" name="username" placeholder="Username" required autofocus autocomplete="username">
    <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</div>
</body>
</html>
"""

MACROS = """
{%- macro controls(s, hexc) -%}
  {% if 'bri' in s %}<div class="row"><label class="l">Brightness</label><input type="range" class="bri" data-key="bri" min="1" max="254" value="{{ s.bri }}"></div>{% endif %}
  {% if 'ct' in s %}<div class="row"><label class="l">Warm ↔ Cool</label><input type="range" class="ct" data-key="ct" min="153" max="500" value="{{ s.ct }}"></div>{% endif %}
  {% if 'xy' in s %}<div class="row"><label class="l">Color</label><input type="color" data-key="hex" value="{{ hexc }}"></div>{% endif %}
{%- endmacro -%}

{%- macro light_card(id, l, light_groups, show_chips) -%}
  {% set st = l.state %}
  {% set hexc = xy_to_hex(st.xy[0], st.xy[1], 254) if 'xy' in st else '#ffb14a' %}
  <div class="card light {{ 'on' if st.on else 'off' }} {{ 'unreachable' if st.get('reachable') == False }}" data-url="/api/light/{{ id }}" style="--glow:{{ hexc }}">
    <div class="head"><div class="dot">💡</div>
      <div class="t"><h3>{{ l.name }}</h3>
        <div class="muted">{{ l.get('productname') or l.get('type') }} · <span data-status>{{ 'On' if st.on else 'Off' }}{% if st.on and 'bri' in st %} · {{ (st.bri / 254 * 100)|round|int }}%{% endif %}</span>{% if st.get('reachable') == False %} · unreachable{% endif %}</div></div>
      <label class="switch"><input type="checkbox" data-key="on" {{ 'checked' if st.on }}><span></span></label></div>
    {% if show_chips and light_groups.get(id) %}
    <div class="chips"><span class="muted">In</span>
      {% for gid, gname, gtype in light_groups[id] %}<a class="chip" href="/?tab=groups&open={{ gid }}" data-open-group="{{ gid }}" title="Open {{ gname }}">{{ {'Room':'🛋️','Zone':'🗺️'}.get(gtype, '🔗') }} {{ gname }}</a>{% endfor %}
    </div>
    {% endif %}
    <div class="ctrl">{{ controls(st, hexc) }}</div>
  </div>
{%- endmacro -%}
"""

HTML_TEMPLATE = MACROS + """
<!DOCTYPE html>
<html lang="en"{% if tab == 'scenes' %} data-theme="dark"{% endif %}>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hue Admin</title>
<script>try{var t=localStorage.theme;if(t)document.documentElement.dataset.theme=t}catch(e){}</script>
{% raw %}
<style>
:root {
  --bg:#f4f5f9; --surface:#fff; --surface-2:#eef0f6; --border:#e2e5ee; --text:#1b1d29; --muted:#6b7086;
  --primary:#6d5dfc; --primary-fg:#fff; --ok:#12a87a; --danger:#e5484d; --shadow:0 1px 3px rgba(20,20,50,.08),0 8px 24px rgba(20,20,50,.06);
  --radius:16px; --glow:#ffb14a;
}
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --bg:#0f1117; --surface:#181b25; --surface-2:#222635; --border:#2a2f40; --text:#eceef6; --muted:#8b91a8;
  --primary:#8b7dff; --primary-fg:#0f1117; --ok:#3ddbb0; --danger:#ff6b70; --shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.3);
}}
:root[data-theme="dark"] {
  --bg:#0f1117; --surface:#181b25; --surface-2:#222635; --border:#2a2f40; --text:#eceef6; --muted:#8b91a8;
  --primary:#8b7dff; --primary-fg:#0f1117; --ok:#3ddbb0; --danger:#ff6b70; --shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.3);
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; -webkit-font-smoothing:antialiased; }
header { position:sticky; top:0; z-index:10; background:color-mix(in srgb, var(--bg) 85%, transparent); backdrop-filter:blur(12px); border-bottom:1px solid var(--border); }
.bar { max-width:1200px; margin:0 auto; padding:12px 20px; display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
.brand { font-weight:700; font-size:1.1rem; display:flex; align-items:center; gap:8px; }
.brand i { width:26px; height:26px; border-radius:8px; background:linear-gradient(135deg,#ffb14a,#ff5f8d,#6d5dfc); display:inline-block; }
nav { display:flex; gap:4px; background:var(--surface-2); padding:4px; border-radius:12px; overflow-x:auto; }
nav a { color:var(--muted); text-decoration:none; font-weight:600; font-size:.9rem; padding:7px 14px; border-radius:9px; white-space:nowrap; }
nav a:hover { color:var(--text); }
nav a.active { background:var(--surface); color:var(--text); box-shadow:var(--shadow); }
.right { margin-left:auto; display:flex; align-items:center; gap:10px; color:var(--muted); font-size:.85rem; }
.icon-btn { background:var(--surface-2); border:1px solid var(--border); color:var(--text); border-radius:10px; padding:6px 10px; cursor:pointer; font-size:.85rem; text-decoration:none; }
main { max-width:1200px; margin:24px auto; padding:0 20px 60px; }
h2 { margin:0 0 4px; font-size:1.3rem; } h3 { margin:0; font-size:1.02rem; }
.sub { color:var(--muted); font-size:.88rem; margin:0 0 18px; }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:16px; }
.card { background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:18px; box-shadow:var(--shadow); position:relative; }
.card.light.on { border-color:color-mix(in srgb, var(--glow) 55%, var(--border)); box-shadow:0 0 0 1px color-mix(in srgb, var(--glow) 25%, transparent), 0 10px 30px color-mix(in srgb, var(--glow) 22%, transparent); }
.card.off .ctrl { opacity:.45; }
.card.unreachable { opacity:.6; }
.head { display:flex; align-items:center; gap:12px; margin-bottom:6px; }
.head .t { flex:1; min-width:0; } .head .t h3 { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.muted { color:var(--muted); font-size:.8rem; }
.dot { width:38px; height:38px; border-radius:12px; background:var(--surface-2); display:grid; place-items:center; font-size:1.2rem; flex:none; }
.card.light.on .dot { background:var(--glow); box-shadow:0 0 16px color-mix(in srgb, var(--glow) 60%, transparent); }
.row { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-top:14px; }
.row label.l { font-size:.82rem; color:var(--muted); min-width:74px; }
.row input[type=range] { flex:1; }
input[type=range] { -webkit-appearance:none; appearance:none; height:8px; border-radius:99px; background:var(--surface-2); outline:none; }
input[type=range]::-webkit-slider-thumb { -webkit-appearance:none; width:20px; height:20px; border-radius:50%; background:#fff; border:2px solid var(--primary); cursor:pointer; box-shadow:0 1px 4px rgba(0,0,0,.25); }
input[type=range]::-moz-range-thumb { width:18px; height:18px; border-radius:50%; background:#fff; border:2px solid var(--primary); cursor:pointer; }
input[type=range].bri { background:linear-gradient(90deg,#3a3a3a,#fff); }
input[type=range].ct { background:linear-gradient(90deg,#9fc4ff,#fff 50%,#ffb457); direction:rtl; }
input[type=color] { -webkit-appearance:none; border:2px solid var(--border); width:36px; height:36px; border-radius:50%; padding:0; cursor:pointer; background:none; overflow:hidden; }
input[type=color]::-webkit-color-swatch-wrapper { padding:0; } input[type=color]::-webkit-color-swatch { border:none; border-radius:50%; }
input[type=text], input[type=password], input[type=datetime-local], select { width:100%; background:var(--surface-2); color:var(--text); border:1px solid var(--border); border-radius:10px; padding:10px 12px; font:inherit; }
input:focus, select:focus { outline:2px solid color-mix(in srgb, var(--primary) 50%, transparent); }
button.btn { background:var(--primary); color:var(--primary-fg); border:0; border-radius:10px; padding:10px 16px; font:inherit; font-weight:600; cursor:pointer; }
button.btn:hover { filter:brightness(1.08); } button.btn.ghost { background:var(--surface-2); color:var(--text); } button.btn.danger { background:var(--danger); color:#fff; }
.switch { position:relative; width:44px; height:26px; flex:none; display:inline-block; }
.switch input { opacity:0; width:0; height:0; }
.switch span { position:absolute; inset:0; background:var(--surface-2); border:1px solid var(--border); border-radius:99px; cursor:pointer; transition:.2s; }
.switch span::before { content:""; position:absolute; height:20px; width:20px; left:2px; top:2px; background:#fff; border-radius:50%; transition:.2s; box-shadow:0 1px 3px rgba(0,0,0,.3); }
.switch input:checked + span { background:var(--primary); border-color:var(--primary); }
.switch input:checked + span::before { transform:translateX(18px); }
.pill { display:inline-flex; align-items:center; gap:4px; padding:3px 9px; border-radius:99px; font-size:.75rem; font-weight:600; background:var(--surface-2); color:var(--muted); }
.pill.ok { background:color-mix(in srgb, var(--ok) 16%, transparent); color:var(--ok); } .pill.bad { background:color-mix(in srgb, var(--danger) 16%, transparent); color:var(--danger); }
.alert { padding:12px 16px; border-radius:12px; margin-bottom:18px; background:color-mix(in srgb, var(--danger) 14%, transparent); color:var(--danger); border:1px solid color-mix(in srgb, var(--danger) 30%, transparent); }
.alert.info { background:color-mix(in srgb, var(--ok) 14%, transparent); color:var(--ok); border-color:color-mix(in srgb, var(--ok) 30%, transparent); }
.form { display:flex; flex-direction:column; gap:12px; } .form label { font-size:.82rem; color:var(--muted); display:block; margin-bottom:4px; }
.inline { display:flex; gap:10px; } .inline input { flex:1; }
.checks { display:grid; grid-template-columns:1fr 1fr; gap:6px; max-height:170px; overflow:auto; background:var(--surface-2); padding:10px; border-radius:10px; font-size:.88rem; }
.checks label { margin:0; color:var(--text); display:flex; align-items:center; gap:6px; }
details summary { cursor:pointer; color:var(--muted); font-size:.85rem; margin-top:14px; }
.reading { display:flex; align-items:center; gap:10px; padding:10px 0; border-top:1px solid var(--border); }
.reading:first-of-type { margin-top:10px; }
.reading .rl { color:var(--muted); font-size:.82rem; width:92px; flex:none; }
.reading .rv { flex:1; font-weight:600; }
.reading .rv small { color:var(--muted); font-weight:500; }
.motion-on { color:var(--ok); } .state-open { color:#e8a317; } .state-bad { color:var(--danger); }
.setting { display:flex; align-items:center; gap:10px; padding:6px 0 6px 102px; font-size:.82rem; color:var(--muted); }
.setting input[type=range] { flex:1; max-width:140px; }
.empty { text-align:center; color:var(--muted); padding:40px 0; }
.toast { position:fixed; bottom:22px; left:50%; transform:translate(-50%,20px); background:var(--text); color:var(--bg); padding:10px 18px; border-radius:99px; font-weight:600; font-size:.9rem; opacity:0; pointer-events:none; transition:.25s; z-index:50; }
.toast.show { opacity:1; transform:translate(-50%,0); } .toast.err { background:var(--danger); color:#fff; }
.chips { display:flex; flex-wrap:wrap; align-items:center; gap:6px; margin-top:10px; }
.chip { display:inline-flex; align-items:center; gap:4px; padding:3px 10px; border-radius:99px; font-size:.76rem; font-weight:600; text-decoration:none; color:var(--primary); background:color-mix(in srgb, var(--primary) 14%, transparent); border:1px solid color-mix(in srgb, var(--primary) 25%, transparent); }
.chip:hover { background:color-mix(in srgb, var(--primary) 26%, transparent); }
.expand { display:grid; place-items:center; width:34px; height:34px; padding:0; flex:none; }
.title-link { color:inherit; text-decoration:none; } .title-link:hover { color:var(--primary); }
dialog#group-modal { width:min(980px,94vw); max-width:94vw; max-height:90vh; padding:0; border:1px solid var(--border); border-radius:20px; background:var(--bg); color:var(--text); box-shadow:0 30px 80px rgba(0,0,0,.45); overflow:hidden; }
dialog#group-modal::backdrop { background:rgba(10,12,20,.55); backdrop-filter:blur(4px); }
body:has(dialog[open]) { overflow:hidden; }
.gm-wrap { max-height:90vh; overflow:auto; padding:18px 22px 26px; }
.gm-top { display:flex; align-items:center; justify-content:space-between; margin-bottom:12px; }
.gm-h { margin:24px 0 12px; font-size:1rem; }
.scene-save { display:flex; gap:10px; } .scene-save input { flex:1; }
.scene-list { margin-top:12px; display:flex; flex-direction:column; gap:8px; max-height:260px; overflow:auto; }
.scene-row { display:flex; align-items:center; justify-content:space-between; gap:10px; background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:8px 12px; }
[hidden] { display:none !important; }
.progress { height:8px; border-radius:99px; background:var(--surface-2); overflow:hidden; margin-top:16px; }
.progress span { display:block; height:100%; width:0; background:linear-gradient(90deg,var(--primary),#ff5f8d); transition:width .8s linear; }
.found-row { display:flex; align-items:center; gap:10px; background:var(--surface-2); border:1px solid var(--border); border-radius:12px; padding:8px 10px; margin-top:8px; }
.found-row input { flex:1; background:var(--surface); }
</style>
{% endraw %}
</head>
<body>
<header><div class="bar">
  <div class="brand"><i></i> Hue Admin</div>
  <nav>
    {% for key, label, adminOnly in [('lights','Lights',False),('groups','Groups',False),('scenes','Scene editor',True),('sensors','Sensors',True),('bridges','Bridges',True),('settings','Schedules',True),('users','Users',True)] %}
    {% if not adminOnly or user.role == 'admin' %}
    <a href="/?tab={{ key }}" class="{{ 'active' if tab == key }}">{{ label }}</a>
    {% endif %}
    {% endfor %}
  </nav>
  <div class="right">
    <span>{{ config.active_bridge or 'No bridge' }}</span>
    <a href="/?tab=account" class="icon-btn">{{ user.username }} · {{ user.role }}</a>
    <a href="/logout" class="icon-btn">Logout</a>
    <button class="icon-btn" id="theme-btn" title="Toggle theme">Theme</button>
  </div>
</div></header>

<main>
{% if error %}<div class="alert">{{ error }}</div>{% endif %}
{% if notice %}<div class="alert info">{{ notice }}</div>{% endif %}

{% if tab == 'bridges' %}
<h2>Bridges</h2><p class="sub">Press the physical link button on your Hue bridge, then connect within 30 seconds.</p>
<div class="grid">
  <div class="card">
    <h3>Connect new bridge</h3>
    <form action="/api/bridge/add" method="POST" class="form" style="margin-top:14px;">
      <input type="text" name="ip" placeholder="Bridge IP, e.g. 192.168.1.50" required>
      <button class="btn" type="submit">Connect bridge</button>
    </form>
  </div>
  {% for ip, user_entry in config.bridges.items() %}
  <div class="card">
    <div class="head"><div class="dot">🌉</div><div class="t"><h3>{{ ip }}</h3><div class="muted">User {{ user_entry[:8] }}…</div></div>
      {% if config.active_bridge == ip %}<span class="pill ok">Active</span>{% endif %}</div>
    <div class="inline" style="margin-top:14px;">
      {% if config.active_bridge != ip %}
      <form action="/api/bridge/set_active" method="POST" style="flex:1"><input type="hidden" name="ip" value="{{ ip }}"><button class="btn" style="width:100%">Set active</button></form>
      {% endif %}
      <form action="/api/bridge/remove" method="POST" onsubmit="return confirm('Forget this bridge?')"><input type="hidden" name="ip" value="{{ ip }}"><button class="btn ghost">Remove</button></form>
    </div>
  </div>
  {% endfor %}
</div>

{% if config.active_bridge %}
<div class="card" id="scan-card" style="margin-top:20px;">
  <div class="head"><div class="dot">📡</div>
    <div class="t"><h3>Find new devices</h3><div class="muted">Searches on the active bridge, {{ config.active_bridge }}</div></div></div>
  <p class="muted" style="margin:8px 0 0;">Power on the new light, or put the switch/sensor in pairing mode, and keep it close to the bridge. A scan takes about a minute. Devices that were paired to another bridge may need a factory reset first.</p>
  <div class="inline" style="margin-top:14px;max-width:520px;">
    <select id="scan-kind" aria-label="Device type"><option value="lights">Lights</option><option value="sensors">Sensors &amp; switches</option></select>
    <button class="btn" id="scan-btn" type="button" style="white-space:nowrap">Scan for new devices</button>
  </div>
  <div id="scan-progress" hidden><div class="progress"><span id="scan-bar"></span></div><div class="muted" id="scan-msg" style="margin-top:6px;"></div></div>
  <div id="scan-results"></div>
</div>
{% endif %}
{% endif %}

{% if tab == 'lights' %}
<h2>Lights</h2><p class="sub">Changes apply instantly. Click a group tag to open that group.</p>
<div class="grid">
{% for id, l in data.lights.items() %}{{ light_card(id, l, light_groups, True) }}
{% else %}<div class="empty">No lights available to you yet.</div>{% endfor %}
</div>
{% endif %}

{% if tab == 'groups' %}
<h2>Groups</h2><p class="sub">Rooms, zones and light groups. Use the expand button to see every light in a group.</p>
{% if user.role == 'admin' %}
<div class="card" style="margin-bottom:20px;">
  <details><summary style="margin:0;color:var(--text);font-weight:600;">+ Create new group</summary>
  <form action="/api/group/create" method="POST" class="form ajax-form-reload" style="margin-top:14px;">
    <input type="text" name="name" placeholder="Group name" required>
    <div class="checks">{% for l_id, l in data.lights.items() %}<label><input type="checkbox" name="lights" value="{{ l_id }}"> {{ l.name }}</label>{% endfor %}</div>
    <button class="btn" type="submit">Create group</button>
  </form></details>
</div>
{% endif %}
<div class="grid">
{% for id, g in data.groups.items() %}
  {% set a = g.action %}
  {% set is_on = g.get('state', {}).get('any_on', a.get('on')) %}
  {% set hexc = xy_to_hex(a.xy[0], a.xy[1], 254) if 'xy' in a else '#ffb14a' %}
  <div class="card light {{ 'on' if is_on else 'off' }}" data-url="/api/group/{{ id }}/action" style="--glow:{{ hexc }}">
    <div class="head"><div class="dot">🛋️</div>
      <div class="t"><h3><a class="title-link" href="/?tab=groups&open={{ id }}" data-open-group="{{ id }}">{{ g.name }}</a></h3><div class="muted">{{ g.type }}{% if g.get('class') %} · {{ g['class'] }}{% endif %} · {{ g.lights|length }} lights</div></div>
      <button class="icon-btn expand" type="button" data-open-group="{{ id }}" title="Open group details" aria-label="Open {{ g.name }}">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg></button>
      <label class="switch"><input type="checkbox" data-key="on" {{ 'checked' if is_on }}><span></span></label></div>
    <div class="ctrl">{{ controls(a, hexc) }}</div>
    {% if user.role == 'admin' %}
    <details><summary>Edit group</summary>
      <form action="/api/group/{{ id }}/edit" method="POST" class="form ajax-form-reload" style="margin-top:12px;">
        <input type="text" name="name" value="{{ g.name }}">
        <div class="checks">{% for l_id, l in data.lights.items() %}<label><input type="checkbox" name="lights" value="{{ l_id }}" {{ 'checked' if l_id in g.lights }}> {{ l.name }}</label>{% endfor %}</div>
        <div class="inline"><button class="btn" style="flex:1" type="submit">Save</button>
        <button class="btn danger" type="button" data-delete="/api/group/{{ id }}/delete" data-confirm="Delete group {{ g.name }}?">Delete</button></div>
      </form>
    </details>
    {% endif %}
  </div>
{% else %}<div class="empty">No groups available to you yet.</div>{% endfor %}
</div>
{% endif %}

{% if tab == 'sensors' %}
<div style="display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:10px;">
  <div><h2>Sensors &amp; controls</h2><p class="sub">Motion, door/window contact, temperature, light level, daylight and switches. Live, refreshes every 5 seconds.</p></div>
  <div class="inline" style="margin-bottom:18px;"><button class="btn ghost" id="unit-btn">°C / °F</button></div>
</div>
<div class="grid" id="sensor-grid"><div class="empty">Loading sensors…</div></div>
{% endif %}

{% if tab == 'settings' %}
<h2>Schedules</h2><p class="sub">Create simple one-off timers on the bridge.</p>
<div class="grid">
  <div class="card">
    <h3>New schedule</h3>
    <form action="/api/schedule/create" method="POST" class="form ajax-form-reload" style="margin-top:14px;">
      <input type="text" name="name" placeholder="Schedule name" required>
      <div><label>Local time</label><input type="datetime-local" name="time" required></div>
      <div><label>Target</label><select name="target">
        <optgroup label="Lights">{% for l_id, l in data.lights.items() %}<option value="lights/{{ l_id }}">{{ l.name }}</option>{% endfor %}</optgroup>
        <optgroup label="Groups">{% for g_id, g in data.groups.items() %}<option value="groups/{{ g_id }}">{{ g.name }}</option>{% endfor %}</optgroup>
      </select></div>
      <div><label>Action</label><select name="action_state"><option value="true">Turn on</option><option value="false">Turn off</option></select></div>
      <button class="btn" type="submit">Add schedule</button>
    </form>
  </div>
  <div class="card">
    <h3>Application</h3>
    <p class="muted" style="margin:10px 0;">Listening on <b>{{ config.host }}:{{ config.port }}</b>. Edit config.json and restart to change.</p>
  </div>
  {% for id, s in data.schedules.items() %}
  <div class="card">
    <div class="head"><div class="dot">⏰</div><div class="t"><h3>{{ s.name }}</h3><div class="muted">{{ s.get('localtime') }}</div></div><span class="pill">{{ s.get('status','') }}</span></div>
    <p class="muted">{{ s.get('description') }}</p>
    <button class="btn danger" data-delete="/api/schedule/delete/{{ id }}" data-confirm="Delete this schedule?">Delete</button>
  </div>
  {% endfor %}
</div>
{% endif %}

{% if tab == 'users' %}
<h2>Users</h2><p class="sub">Create accounts for family members and choose which rooms each one can control. Admins can control everything.</p>
<div class="grid">
  <div class="card">
    <h3>Add user</h3>
    <form action="/api/user/add" method="POST" class="form ajax-form-reload" style="margin-top:14px;">
      <input type="text" name="username" placeholder="Username" required autocomplete="off">
      <input type="text" name="password" placeholder="Password" required autocomplete="new-password">
      <div><label>Role</label><select name="role"><option value="member">Family member</option><option value="admin">Admin</option></select></div>
      <div><label>Rooms this user can control (ignored for admins)</label>
        <div class="checks">
          {% for g_id, g in data.groups.items() %}<label><input type="checkbox" name="rooms" value="{{ g_id }}"> {{ g.name }}</label>{% endfor %}
          {% if not data.groups %}<span class="muted">Connect a bridge first to choose rooms.</span>{% endif %}
        </div>
      </div>
      <button class="btn" type="submit">Add user</button>
    </form>
  </div>
  {% for uname, u in config.users.items() %}
  <div class="card">
    <div class="head"><div class="dot">{{ '🛡️' if u.role == 'admin' else '👤' }}</div>
      <div class="t"><h3>{{ uname }}</h3><div class="muted">{{ 'Administrator · full access' if u.role == 'admin' else (u.rooms|length ~ ' room(s)') }}</div></div>
      {% if uname == user.username %}<span class="pill">You</span>{% endif %}</div>
    <form action="/api/user/update/{{ uname }}" method="POST" class="form ajax-form-reload" style="margin-top:14px;">
      <div><label>Role</label><select name="role"><option value="member" {{ 'selected' if u.role != 'admin' }}>Family member</option><option value="admin" {{ 'selected' if u.role == 'admin' }}>Admin</option></select></div>
      <div><label>Rooms</label><div class="checks">{% for g_id, g in data.groups.items() %}<label><input type="checkbox" name="rooms" value="{{ g_id }}" {{ 'checked' if g_id in u.rooms }}> {{ g.name }}</label>{% endfor %}</div></div>
      <input type="text" name="password" placeholder="New password (leave blank to keep)" autocomplete="new-password">
      <div class="inline"><button class="btn" style="flex:1" type="submit">Save</button>
      {% if uname != user.username %}<button class="btn danger" type="button" data-delete="/api/user/delete/{{ uname }}" data-confirm="Delete user {{ uname }}?">Delete</button>{% endif %}
      </div>
    </form>
  </div>
  {% endfor %}
</div>
{% endif %}

{% if tab == 'scenes' %}
<style>
{% raw %}
#se .se-bar{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-bottom:18px}
#se .sp{flex:1}
#se select,#se input[type=number],#se input[type=text]{width:auto}
#se #se-name{min-width:18ch;font-weight:600}
#se button:disabled{opacity:.5;cursor:not-allowed}
.se-app{display:grid;grid-template-columns:260px minmax(0,1fr);gap:22px;align-items:start}
@media(max-width:820px){.se-app{grid-template-columns:1fr}}
#se-pal h4{margin:18px 0 8px;font-size:.95rem}
#se-pal h4:first-child{margin-top:0}
#se .list{display:flex;flex-wrap:wrap;gap:6px}
#se .obj{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;background:var(--surface);border:1px solid var(--border);cursor:grab;user-select:none;font-size:.88rem}
#se .obj.g{border-radius:6px;border-left:4px solid var(--ok)}
#se .obj.l{border-radius:99px;border-left:4px solid var(--glow)}
#se .obj.miss{border-style:dashed}
#se .obj i{font-style:normal;cursor:pointer;color:var(--muted)}
#se .obj i:hover{color:var(--danger)}
#se .act{display:flex;gap:10px;align-items:center;padding:8px 10px;margin-bottom:6px;background:var(--surface);border:1px solid var(--border);border-radius:10px;cursor:grab}
#se .act>span{font-size:1.3rem}
#se .step{position:relative;margin:0 0 12px 36px;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:10px 14px;box-shadow:var(--shadow)}
#se .step::before{content:"";position:absolute;left:-25px;top:0;bottom:-13px;border-left:2px solid var(--border)}
#se .step::after{content:attr(data-n);position:absolute;left:-36px;top:9px;width:22px;height:22px;border-radius:50%;background:var(--primary);color:var(--primary-fg);font-size:.75rem;font-weight:700;display:grid;place-items:center}
#se .step.sel{border-color:var(--primary)}
#se .step.mb{box-shadow:0 -4px 0 var(--primary)}
#se .step.ma{box-shadow:0 4px 0 var(--primary)}
#se .sh{display:flex;align-items:center;gap:8px}
#se .grip{cursor:grab;color:var(--muted);font-size:1.1rem;padding:0 4px}
#se .x{border:0;background:none;color:var(--muted);cursor:pointer;font-size:1rem}
#se .x:hover{color:var(--danger)}
#se .tz{display:flex;flex-wrap:wrap;gap:6px;align-items:center;min-height:38px;margin:8px 0 2px;padding:6px;border:1px dashed var(--border);border-radius:8px}
#se .tz.over{border-color:var(--primary);background:color-mix(in srgb,var(--primary) 10%,transparent)}
#se .f{display:flex;gap:10px;align-items:center;margin-top:8px}
#se .f>label{width:84px;flex:none;color:var(--muted)}
#se .c{display:flex;flex-wrap:wrap;gap:8px;align-items:center;flex:1}
#se input[type=number]{width:80px}
#se .dur{display:inline-flex;gap:4px}
#se input[type=range]{width:170px}
#se input.kel{background:linear-gradient(90deg,#ffb457,#fff 50%,#9fc4ff)}
#se output{min-width:5ch;font-variant-numeric:tabular-nums}
#se .sws{display:inline-flex;gap:6px;align-items:center;flex-wrap:wrap}
#se .sw{width:22px;height:22px;border-radius:50%;box-shadow:0 0 0 1px var(--border);border:2px solid var(--surface);cursor:pointer;display:inline-block}
#se .chk{display:flex;gap:6px;align-items:center}
#se-end{margin-left:36px;padding:18px;text-align:center;border:2px dashed var(--border);border-radius:12px;color:var(--muted)}
#se-end.over{border-color:var(--primary);color:var(--text)}
#se-pvw{margin:18px 0 0 36px}
#se-pvw h4{margin:0 0 8px;font-size:.95rem}
#se .prow{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
#se-log{margin:10px 0 0;max-height:280px;overflow:auto;padding:8px;background:var(--surface);border:1px solid var(--border);border-radius:8px;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap}
#se details{margin:16px 0 0 36px}
#se textarea{width:100%;height:240px;margin-top:8px;padding:8px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:8px;font:12px/1.4 ui-monospace,Menlo,Consolas,monospace}
{% endraw %}
</style>
<h2>Scene editor</h2>
<p class="sub">Build timed sequences from the rooms and lights on {{ config.active_bridge }}. Export them, or preview them here with the runner.</p>
<div id="se">
  <div class="se-bar">
    <input id="se-name" type="text" aria-label="Scene name" placeholder="Scene name">
    <label class="muted">Repeat <select id="se-rm"><option value="once">once</option><option value="count">N times</option><option value="forever">forever</option></select></label>
    <input id="se-rc" type="number" min="2" value="2" aria-label="Repeat count" hidden>
    <span class="sp"></span>
    <button class="btn ghost" id="se-new" type="button">New</button>
    <button class="btn ghost" id="se-imp" type="button">Open scene</button>
    <button class="btn" id="se-exp" type="button">Export</button>
    <input type="file" id="se-fi" accept=".json,application/json" hidden>
  </div>
  <div class="se-app">
    <aside id="se-pal"></aside>
    <div id="se-main">
      <div id="se-tl"></div>
      <div id="se-end">Drag an action here, or drop a room or light to start a step</div>
      <section id="se-pvw">
        <h4>Preview with the runner</h4>
        <div class="prow">
          <button class="btn ghost" id="se-dry" type="button">Dry run</button>
          <button class="btn" id="se-play" type="button">Play on lights</button>
          <button class="btn ghost" id="se-stop" type="button" disabled>Stop</button>
          <label class="muted">Speed <select id="se-spd"><option>1</option><option>2</option><option>5</option><option>10</option><option>30</option></select>&times;</label>
          <label class="chk muted"><input type="checkbox" id="se-once" checked> One pass only</label>
        </div>
        <p class="muted">Dry run sends nothing. Play changes your real lights and leaves them as the scene ends.</p>
        <pre id="se-log" hidden></pre>
      </section>
      <details><summary>JSON preview</summary><textarea id="se-pv" readonly aria-label="Export preview"></textarea></details>
    </div>
  </div>
</div>
{% endif %}

{% if tab == 'account' %}
<h2>Account</h2><p class="sub">Signed in as {{ user.username }} ({{ user.role }}).</p>
<div class="grid">
  <div class="card">
    <h3>Change password</h3>
    <form action="/api/user/password" method="POST" class="form ajax-form-reload" style="margin-top:14px;">
      <input type="password" name="current_password" placeholder="Current password" required autocomplete="current-password">
      <input type="password" name="new_password" placeholder="New password" required autocomplete="new-password">
      <button class="btn" type="submit">Update password</button>
    </form>
  </div>
  {% if user.role != 'admin' %}
  <div class="card"><h3>Your access</h3><p class="muted" style="margin-top:10px;">You can control {{ user.rooms|length }} room(s). Ask an admin to change this from the Users tab.</p></div>
  {% endif %}
</div>
{% endif %}

</main>
{% if tab in ('lights', 'groups') %}
<dialog id="group-modal" aria-label="Group details"><div class="gm-wrap">
  <div class="gm-top"><span class="muted">Group details</span><button class="icon-btn" id="gm-close" type="button" aria-label="Close">✕</button></div>
  <div id="gm-body"></div>
  <div id="gm-scenes"></div>
</div></dialog>
{% endif %}
<div class="toast" id="toast"></div>

{% raw %}
<script>
const $ = (s, r = document) => r.querySelector(s);
const toastEl = $('#toast');
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
let toastTimer;
function toast(msg, err) {
  toastEl.textContent = msg; toastEl.className = 'toast show' + (err ? ' err' : '');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => toastEl.className = 'toast', err ? 3500 : 1400);
}
async function post(url, data, isForm) {
  const opts = { method: 'POST' };
  if (isForm) opts.body = data; else { opts.headers = { 'Content-Type': 'application/json' }; opts.body = JSON.stringify(data || {}); }
  try {
    const res = await fetch(url, opts); const out = await res.json();
    if (!out.success) { toast(out.error || 'Request failed', true); return null; }
    return out;
  } catch (e) { toast('Network error', true); return null; }
}
async function getJSON(url) { const r = await fetch(url); const o = await r.json(); if (!o.success) throw new Error(o.error); return o; }

// Theme
const root = document.documentElement;
if (localStorage.theme) root.dataset.theme = localStorage.theme;
$('#theme-btn').onclick = () => {
  const dark = matchMedia('(prefers-color-scheme: dark)').matches;
  const cur = root.dataset.theme || (dark ? 'dark' : 'light');
  root.dataset.theme = localStorage.theme = cur === 'dark' ? 'light' : 'dark';
};

// Live light / group controls (debounced)
const timers = {};
function sendLive(card, key, value) {
  const id = card.dataset.url + key;
  clearTimeout(timers[id]);
  timers[id] = setTimeout(async () => {
    const out = await post(card.dataset.url, { [key]: value });
    if (out && key === 'hex') card.style.setProperty('--glow', value);
    if (out && window.gmAfterPost && card.closest('#group-modal')) window.gmAfterPost();
  }, 120);
}
function refreshStatus(card) {
  const s = card.querySelector('[data-status]'); if (!s) return;
  const on = card.querySelector('[data-key="on"]'), bri = card.querySelector('[data-key="bri"]');
  let t = on && on.checked ? 'On' : 'Off';
  if (on && on.checked && bri) t += ' · ' + Math.round(bri.value / 254 * 100) + '%';
  s.textContent = t;
}
document.addEventListener('input', e => {
  const el = e.target, card = el.closest('[data-url]');
  if (!card || !el.dataset.key) return;
  let v = el.type === 'checkbox' ? el.checked : (el.type === 'range' ? Number(el.value) : el.value);
  if (el.dataset.key === 'on') { card.classList.toggle('on', v); card.classList.toggle('off', !v); }
  if (el.dataset.key === 'hex') card.style.setProperty('--glow', v);
  refreshStatus(card);
  sendLive(card, el.dataset.key, v);
});

// Forms
document.querySelectorAll('.ajax-form-reload').forEach(f => f.addEventListener('submit', async e => {
  e.preventDefault();
  if (await post(f.action, new FormData(f), true)) location.reload();
}));
document.querySelectorAll('[data-delete]').forEach(b => b.addEventListener('click', async () => {
  if (confirm(b.dataset.confirm || 'Are you sure?') && await post(b.dataset.delete, {})) location.reload();
}));

// Device scan (Bridges tab)
const scanCard = $('#scan-card');
if (scanCard) {
  const btn = $('#scan-btn'), kindSel = $('#scan-kind'), prog = $('#scan-progress');
  const bar = $('#scan-bar'), msg = $('#scan-msg'), results = $('#scan-results');
  const SCAN_MS = 60000;   // a Hue search runs ~40-60s
  let pollTimer = null, startedAt = 0, lastKind = 'lights';

  function renderResults(o, kind) {
    const label = kind === 'sensors' ? 'sensors & switches' : 'lights';
    let h = '';
    if (o.found.length) {
      h += `<h3 class="gm-h">New ${label} found (${o.found.length})</h3>`;
      h += o.found.map(f => `<div class="found-row" data-id="${esc(f.id)}"><input type="text" maxlength="32" value="${esc(f.name)}" aria-label="Device name"><button class="btn ghost" type="button" data-rename>Rename</button></div>`).join('');
      h += `<p class="muted" style="margin-top:10px;">${kind === 'lights' ? 'They are on the Lights tab now. Add them to a room with Groups → Edit group.' : 'They now appear on the Sensors tab.'}</p>`;
    } else if (!o.scanning) {
      h += `<p class="muted" style="margin-top:14px;">No new ${label} found. Check that the device is powered on (or in pairing mode) and close to the bridge, then scan again.</p>`;
    }
    if (!o.scanning && o.lastscan && o.lastscan !== 'none' && o.lastscan !== 'active') {
      const t = new Date(o.lastscan + 'Z');
      h += `<p class="muted">Scan finished ${isNaN(t) ? esc(o.lastscan) : esc(t.toLocaleString())}.</p>`;
    }
    results.innerHTML = h;
  }
  function setBusy(busy) { btn.disabled = busy; kindSel.disabled = busy; btn.textContent = busy ? 'Scanning…' : 'Scan for new devices'; }
  function finish(o, kind) {
    clearTimeout(pollTimer); setBusy(false);
    bar.style.width = '100%'; setTimeout(() => { prog.hidden = true; bar.style.width = '0'; }, 800);
    renderResults(o, kind);
    toast(o.found.length ? `Found ${o.found.length} new device${o.found.length > 1 ? 's' : ''}` : 'Scan finished: nothing new');
  }
  async function poll(kind) {
    try {
      const o = await getJSON(`/api/bridge/scan/status?kind=${kind}`);
      const elapsed = Date.now() - startedAt;
      // the bridge can take a moment to flip to "active", so don't trust an early "not scanning"
      if ((o.scanning || elapsed < 5000) && elapsed < SCAN_MS * 2) {
        bar.style.width = Math.min(95, 3 + elapsed / SCAN_MS * 92) + '%';
        msg.textContent = `Scanning… ${Math.round(elapsed / 1000)}s (usually 40–60s)`;
        if (o.found.length) renderResults(o, kind);
        pollTimer = setTimeout(() => poll(kind), 3000);
      } else finish(o, kind);
    } catch (e) { clearTimeout(pollTimer); setBusy(false); prog.hidden = true; toast(e.message, true); }
  }
  function begin(kind) {
    lastKind = kind; startedAt = Date.now(); setBusy(true); prog.hidden = false; bar.style.width = '3%';
    msg.textContent = 'Starting scan…'; clearTimeout(pollTimer); pollTimer = setTimeout(() => poll(kind), 1500);
  }
  btn.onclick = async () => {
    const kind = kindSel.value; results.innerHTML = '';
    btn.disabled = true;
    if (await post('/api/bridge/scan', { kind })) begin(kind); else btn.disabled = false;
  };
  results.addEventListener('click', async e => {
    const b = e.target.closest('[data-rename]'); if (!b) return;
    const row = b.closest('[data-id]'), name = $('input', row).value.trim();
    if (!name) { toast('Enter a name', true); return; }
    if (await post(`/api/device/${lastKind}/${row.dataset.id}/rename`, { name })) toast('Renamed');
  });
  // If a scan is already running (e.g. page was reloaded mid-scan), pick it back up
  getJSON('/api/bridge/scan/status?kind=lights').then(o => { if (o.scanning) { kindSel.value = 'lights'; begin('lights'); } }).catch(() => {});
}

// Group modal: live light status + scenes
const gm = $('#group-modal');
if (gm) {
  const bodyEl = $('#gm-body'), scenesEl = $('#gm-scenes');
  let gmId = null, gmTimer = null, quietUntil = 0, dirty = false, pointerDown = false;
  const colorFocused = () => document.activeElement && document.activeElement.type === 'color' && gm.contains(document.activeElement);

  async function loadPanel(force) {
    if (!gmId) return;
    const blocked = () => pointerDown || colorFocused() || (!force && Date.now() < quietUntil);
    if (blocked()) return;
    try {
      const o = await getJSON(`/api/group/${gmId}/panel`);
      if (!blocked()) bodyEl.innerHTML = o.html;
    } catch (e) { bodyEl.innerHTML = `<div class="alert">${esc(e.message)}</div>`; }
  }
  async function loadScenes() {
    try { scenesEl.innerHTML = (await getJSON(`/api/group/${gmId}/scenes`)).html; }
    catch (e) { scenesEl.innerHTML = ''; }
  }
  window.openGroup = async function (id) {
    gmId = String(id); dirty = false; quietUntil = 0;
    bodyEl.innerHTML = '<div class="empty">Loading…</div>'; scenesEl.innerHTML = '';
    if (!gm.open) gm.showModal();
    clearInterval(gmTimer);
    gmTimer = setInterval(() => { if (gm.open) loadPanel(false); }, 4000);
    await Promise.all([loadPanel(true), loadScenes()]);
  };
  window.gmAfterPost = () => setTimeout(() => loadPanel(true), 700);

  gm.addEventListener('input', () => { quietUntil = Date.now() + 3000; dirty = true; });
  gm.addEventListener('pointerdown', () => { pointerDown = true; });
  ['pointerup', 'pointercancel'].forEach(t => window.addEventListener(t, () => { pointerDown = false; }));
  $('#gm-close').onclick = () => gm.close();
  gm.addEventListener('click', e => { if (e.target === gm) gm.close(); });   // backdrop click
  gm.addEventListener('close', () => {
    clearInterval(gmTimer); gmId = null;
    const u = new URL(location.href); u.searchParams.delete('open'); history.replaceState(null, '', u);
    if (dirty) location.reload();   // refresh the cards behind the modal
  });

  scenesEl.addEventListener('click', async e => {
    const btn = e.target.closest('button'); if (!btn) return;
    if (btn.hasAttribute('data-save-scene')) {
      const input = $('#scene-name', scenesEl), name = input.value.trim();
      if (!name) { toast('Enter a scene name', true); input.focus(); return; }
      btn.disabled = true;
      const out = await post(`/api/group/${gmId}/scene`, { name });
      btn.disabled = false;
      if (out) { toast('Scene saved'); loadScenes(); }
    } else if (btn.dataset.recallScene) {
      const out = await post(`/api/group/${gmId}/scene/${btn.dataset.recallScene}/recall`, {});
      if (out) { toast('Scene applied'); dirty = true; setTimeout(() => loadPanel(true), 900); }
    } else if (btn.dataset.deleteScene) {
      if (confirm('Delete this scene?') && await post(`/api/group/${gmId}/scene/${btn.dataset.deleteScene}/delete`, {})) { toast('Scene deleted'); loadScenes(); }
    }
  });
  scenesEl.addEventListener('keydown', e => {
    if (e.key === 'Enter' && e.target.id === 'scene-name') { e.preventDefault(); $('[data-save-scene]', scenesEl).click(); }
  });
}
// Any element with data-open-group (expand button, group tags on lights) opens the modal in place
document.addEventListener('click', e => {
  const t = e.target.closest('[data-open-group]');
  if (t && window.openGroup) { e.preventDefault(); window.openGroup(t.dataset.openGroup); }
});
{ const op = new URLSearchParams(location.search).get('open'); if (op && window.openGroup) window.openGroup(op); }

// Sensors
const sg = $('#sensor-grid');
if (sg) {
  let useF = localStorage.unit === 'F';
  const icons = { presence: '🚶', temperature: '🌡️', light: '☀️', switch: '🎛️', daylight: '🌅', contact: '🚪', generic: '📟' };
  let devices = [], notice = '';
  const ago = iso => {
    if (!iso) return 'never';
    const s = Math.max(0, (Date.now() - new Date(iso + 'Z')) / 1000);
    if (s < 60) return 'just now'; if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago'; return Math.floor(s / 86400) + 'd ago';
  };
  const toggle = (sid, cfg, on, v2) => `<label class="switch"><input type="checkbox" data-sensor="${sid}" data-cfg="${cfg}" data-v2="${v2 || ''}" ${on ? 'checked' : ''}><span></span></label>`;
  function readingHTML(r) {
    let val = '';
    if (r.kind === 'temperature') {
      val = r.celsius == null ? '–' : (useF ? (r.celsius * 9 / 5 + 32).toFixed(1) + ' °F' : r.celsius.toFixed(1) + ' °C');
    } else if (r.kind === 'light') {
      val = r.lux == null ? '–' : `${r.lux} lx <small>${r.dark ? 'dark' : r.daylight ? 'daylight' : ''}</small>`;
    } else if (r.kind === 'presence') {
      val = `<span class="${r.active ? 'motion-on' : ''}">${r.active ? '● ' : '○ '}${esc(r.value)}</span>`;
    } else if (r.kind === 'contact') {
      val = `<span class="${r.active ? 'state-open' : ''}">${r.active ? '● ' : '○ '}${esc(r.value)}</span>`;
    } else if (r.kind === 'tamper') {
      val = `<span class="${r.active ? 'state-bad' : ''}">${esc(r.value)}</span>`;
    } else val = esc(r.value);
    let html = `<div class="reading"><span class="rl">${esc(r.label)}</span><span class="rv">${val}</span>${r.enabled != null ? toggle(r.id, 'on', r.enabled, r.v2) : ''}</div>`;
    if (r.settings.sensitivity) {
      const s = r.settings.sensitivity;
      html += `<div class="setting">Sensitivity <input type="range" min="0" max="${s.max}" value="${s.value}" data-sensor="${r.id}" data-cfg="sensitivity"> <b>${s.value}/${s.max}</b></div>`;
    }
    if ('ledindication' in r.settings) html += `<div class="setting">LED indicator ${toggle(r.id, 'ledindication', r.settings.ledindication)}</div>`;
    return html;
  }
  function render() {
    const banner = notice ? `<div class="alert" style="grid-column:1/-1;margin:0">${esc(notice)}</div>` : '';
    if (!devices.length) { sg.innerHTML = banner + '<div class="empty">No sensors found on this bridge.</div>'; return; }
    sg.innerHTML = banner + devices.map(d => `
      <div class="card"><div class="head"><div class="dot">${icons[d.kind] || icons.generic}</div>
        <div class="t"><h3>${esc(d.name)}</h3><div class="muted">${esc(d.model)} · updated ${ago(d.lastupdated)}</div></div>
        ${d.battery != null ? `<span class="pill ${d.battery < 20 ? 'bad' : 'ok'}">🔋 ${d.battery}%</span>` : ''}
        ${d.reachable === false ? '<span class="pill bad">offline</span>' : ''}</div>
        ${d.readings.map(readingHTML).join('')}</div>`).join('');
  }
  async function refresh() {
    if (document.activeElement && document.activeElement.type === 'range' && sg.contains(document.activeElement)) return;
    try { const o = await getJSON('/api/sensors'); devices = o.devices; notice = o.notice || ''; render(); }
    catch (e) { sg.innerHTML = `<div class="alert">${esc(e.message)}</div>`; }
  }
  sg.addEventListener('change', async e => {
    const el = e.target; if (!el.dataset.sensor) return;
    const v = el.type === 'checkbox' ? el.checked : Number(el.value);
    const v2 = el.dataset.v2;   // contact sensors live on the bridge's v2 API
    const url = v2 ? `/api/v2/${v2}/${el.dataset.sensor}` : `/api/sensor/${el.dataset.sensor}/config`;
    if (await post(url, v2 ? { enabled: v } : { [el.dataset.cfg]: v })) { toast('Saved'); refresh(); }
  });
  $('#unit-btn').onclick = () => { useF = !useF; localStorage.unit = useF ? 'F' : 'C'; render(); };
  refresh(); setInterval(refresh, 5000);
}
</script>
{% endraw %}
{% if tab == 'scenes' %}
<script type="application/json" id="se-data">{{ inventory|tojson }}</script>
<script>
{% raw %}
(function(){
'use strict';
// Uses phadmin's own $, esc, toast, post and getJSON. Rooms and lights come from the server (active bridge).
const DATA=JSON.parse($('#se-data').textContent);
const byName=(a,b)=>a.name.localeCompare(b.name);
const T={l:Object.entries(DATA.lights).map(([id,x])=>({id,name:x.name||'Light '+id})).sort(byName),
  g:Object.entries(DATA.groups).map(([id,x])=>({id,name:x.name||'Group '+id,lights:x.lights||[]})).sort(byName)};
const X={};  // targets from an opened file that this bridge doesn't have
const TITLES={set:'Set state',fade:'Dim / brighten',wait:'Timer'};
const fresh=()=>({name:'My scene',repeat:{mode:'once',count:2},steps:[]});
const DRAFT='phadmin-scene-draft';
let S=fresh(),sel=-1,drag=null;
try{const d=JSON.parse(localStorage.getItem(DRAFT));if(d&&Array.isArray(d.steps)&&d.repeat)S=d}catch(_){}
const save=()=>{try{localStorage.setItem(DRAFT,JSON.stringify(S))}catch(_){}};
const key=(k,o)=>k+':'+(o.id||'name:'+o.name);
const find=k=>(k[0]==='g'?T.g:T.l).find(o=>key(k[0],o)===k)||X[k];
const inLib=k=>(k[0]==='g'?T.g:T.l).some(o=>key(k[0],o)===k);
const nameOf=k=>{const o=find(k);return o?o.name:k.replace(/^[gl]:(name:)?/,'')};
const setP=(o,p,v)=>{const a=p.split('.');while(a.length>1)o=o[a.shift()];o[a[0]]=v};

function newStep(type,t=[],preset){
  if(type==='set'){const rc=preset==='randcolor';return{type,t,power:rc?'keep':'on',bm:'keep',bri:100,color:{mode:rc?'list':'keep',hex:'#ff8800',kelvin:2700,hexes:rc?['#ff3b30','#34c759','#0a84ff','#ffcc00']:[]}}}
  if(type==='fade')return{type,t,fm:'current',from:100,to:0,secs:600,wait:true};
  return{type:'wait',mode:preset==='randwait'?'random':'fixed',secs:5,min:2,max:10};
}

/* ---------- step controls ---------- */
const opts=(cur,a)=>a.map(([v,l])=>`<option value="${v}"${v===cur?' selected':''}>${l}</option>`).join('');
const row=(l,i)=>`<div class="f"><label>${l}</label><div class="c">${i}</div></div>`;
const sl=(k,v,min,max,step,cls,txt)=>`<input type="range" class="${cls}" data-k="${k}" min="${min}" max="${max}" step="${step}" value="${v}"><output>${txt}</output>`;
const dur=(k,v)=>{const m=v>=60&&v%30===0;return`<span class="dur" data-dk="${k}"><input type="number" min="0" step="any" value="${m?v/60:v}" aria-label="Duration"><select aria-label="Unit"><option value="1">sec</option><option value="60"${m?' selected':''}>min</option></select></span>`};
const colorCtl=c=>c.mode==='fixed'?`<input type="color" data-k="color.hex" value="${esc(c.hex)}" aria-label="Color">`
  :c.mode==='white'?sl('color.kelvin',c.kelvin,2000,6500,100,'kel',c.kelvin+' K')
  :c.mode==='list'?`<span class="sws">${c.hexes.map((h,j)=>`<i class="sw" style="background:${esc(h)}" data-rs="${j}" title="Remove this color"></i>`).join('')}<input type="color" value="#ff3b30" aria-label="Color to add"><button class="btn ghost" data-addc type="button">+ add</button></span>`
  :c.mode==='any'?'<span class="muted">A new random color each time</span>':'';
function body(s){
  if(s.type==='wait')return row('Pause',`<select data-k="mode">${opts(s.mode,[['fixed','for a set time'],['random','for a random time']])}</select>`)
    +(s.mode==='random'?row('Between',dur('min',s.min)+' and '+dur('max',s.max)):row('Duration',dur('secs',s.secs)));
  if(s.type==='fade')return row('From',`<select data-k="fm">${opts(s.fm,[['current','current brightness'],['set','a set brightness']])}</select>`+(s.fm==='set'?sl('from',s.from,0,100,1,'',s.from+'%'):''))
    +row('To',sl('to',s.to,0,100,1,'',s.to+'%')+'<span class="muted">0% turns the light off at the end</span>')
    +row('Over',dur('secs',s.secs))
    +row('',`<label class="chk"><input type="checkbox" data-k="wait"${s.wait?' checked':''}> Wait until finished before the next step</label>`);
  const c=s.color;
  return row('Power',`<select data-k="power">${opts(s.power,[['keep','No change'],['on','Turn on'],['off','Turn off']])}</select>`)
    +row('Brightness',`<select data-k="bm">${opts(s.bm,[['keep','No change'],['set','Set to…']])}</select>`+(s.bm==='set'?sl('bri',s.bri,1,100,1,'',s.bri+'%'):''))
    +row('Color',`<select data-k="color.mode">${opts(c.mode,[['keep','No change'],['fixed','Color'],['white','White, warm to cool'],['list','Random from my colors'],['any','Any random color']])}</select>`+colorCtl(c));
}

/* ---------- rendering ---------- */
function render(){
  $('#se-tl').innerHTML=S.steps.map((s,i)=>`<div class="step${sel===i?' sel':''}" data-i="${i}" data-n="${i+1}">
    <div class="sh"><span class="grip" draggable="true" data-drag="step" data-i="${i}" title="Drag to reorder">⠿</span><b>${TITLES[s.type]}</b><span class="sp"></span><button class="x" data-del type="button" title="Delete step" aria-label="Delete step">✕</button></div>
    ${s.t?`<div class="tz">${s.t.map(k=>`<span class="obj ${k[0]}${inLib(k)?'':' miss'}"${inLib(k)?'':' title="Not found on this bridge"'}>${k[0]==='g'?'🛋️':'💡'} ${inLib(k)?'':'⚠ '}${esc(nameOf(k))}<i data-rt="${esc(k)}" title="Remove">×</i></span>`).join('')||'<span class="muted">Drop rooms or lights here</span>'}</div>`:''}
    ${body(s)}</div>`).join('');
  preview();
}
function pal(){
  const ch=(k,o)=>`<span class="obj ${k}" draggable="true" data-drag="target" data-key="${esc(key(k,o))}">${k==='g'?'🛋️':'💡'} ${esc(o.name)}</span>`;
  const acts=[['set','','🎚️','Set state','On/off, brightness, color'],['fade','','🌗','Dim / brighten','Fade over time'],['wait','','⏱️','Timer','Pause the sequence'],['wait','randwait','🎲','Random timer','Pause for a random time'],['set','randcolor','🌈','Random color','Pick a color at random']];
  const none='<span class="muted">none on this bridge</span>';
  $('#se-pal').innerHTML=`<h4>Rooms &amp; zones</h4><div class="list">${T.g.map(o=>ch('g',o)).join('')||none}</div>
    <h4>Lights</h4><div class="list">${T.l.map(o=>ch('l',o)).join('')||none}</div>
    <h4>Actions</h4>${acts.map(([t,p,i,n,d])=>`<div class="act" draggable="true" data-drag="action" data-type="${t}" data-preset="${p}"><span>${i}</span><div><b>${n}</b><div class="muted">${d}</div></div></div>`).join('')}
    <p class="muted">Drag onto the timeline, or click. Drop a room or light onto a step to aim it there.</p>`;
}
const sync=()=>{$('#se-name').value=S.name;$('#se-rm').value=S.repeat.mode;$('#se-rc').value=S.repeat.count;$('#se-rc').hidden=S.repeat.mode!=='count'};

/* ---------- export / open ---------- */
function build(){
  const used=new Set();S.steps.forEach(s=>(s.t||[]).forEach(k=>used.add(k)));
  const targets={};used.forEach(k=>{const o=find(k);targets[k]=Object.assign({type:k[0]==='g'?'group':'light',name:nameOf(k)},o&&o.id?{id:o.id}:{},o&&o.lights?{lights:o.lights}:{})});
  const steps=S.steps.map(s=>{
    if(s.type==='wait')return s.mode==='random'?{type:'wait',random:{min:s.min,max:Math.max(s.min,s.max)}}:{type:'wait',seconds:s.secs};
    if(s.type==='fade')return{type:'fade',targets:s.t,from:s.fm==='set'?s.from:'current',to:s.to,seconds:s.secs,wait:s.wait};
    const o={type:'set',targets:s.t},c=s.color;
    if(s.power!=='keep')o.power=s.power;
    if(s.bm==='set')o.brightness=s.bri;
    if(c.mode==='fixed')o.color={mode:'fixed',hex:c.hex};
    else if(c.mode==='white')o.color={mode:'white',kelvin:c.kelvin,mirek:Math.max(153,Math.min(500,Math.round(1e6/c.kelvin)))};
    else if(c.mode==='list')o.color={mode:'random_choice',hexes:c.hexes};
    else if(c.mode==='any')o.color={mode:'random_any'};
    return o;
  });
  const r=S.repeat;
  return{format:'hue-scene-sequence',version:1,name:S.name,repeat:r.mode==='count'?{mode:'count',count:r.count}:{mode:r.mode},targets,steps,
    notes:'Steps run in order. Brightness is 0-100%. Colors are sRGB hex; white uses kelvin (mirek = 1,000,000 / kelvin). A fade to 0% turns the light off at the end. A fade with wait=false lets the next step start straight away. Random choices are made fresh each time a step runs. A group target applies to all its lights.'};
}
const preview=()=>{$('#se-pv').value=JSON.stringify(build(),null,2);save()};
function check(){
  if(!S.steps.length)return'Add at least one step first.';
  for(const[i,s]of S.steps.entries()){
    if(s.t&&!s.t.length)return`Step ${i+1} needs a room or light. Drop one onto it.`;
    if(s.type==='set'&&s.color.mode==='list'&&!s.color.hexes.length)return`Step ${i+1}: add at least one color to pick from.`;
    if(s.type==='set'&&s.power==='keep'&&s.bm==='keep'&&s.color.mode==='keep')return`Step ${i+1} changes nothing. Choose power, brightness or color.`;
  }
  return'';
}
function fromJSON(o){
  if(!o||o.format!=='hue-scene-sequence')throw new Error('That file is not a Hue scene export.');
  const map={};
  for(const[k,v]of Object.entries(o.targets||{})){
    const kind=v.type==='group'?'g':'l',list=kind==='g'?T.g:T.l;
    const live=list.find(x=>v.id&&x.id===v.id)||list.find(x=>x.name.toLowerCase()===(v.name||'').toLowerCase());
    if(live)map[k]=key(kind,live);
    else{const x={name:v.name,id:v.id,lights:v.lights},nk=key(kind,x);X[nk]=x;map[k]=nk}
  }
  S.name=o.name||'Imported scene';const r=o.repeat||{};S.repeat={mode:r.mode||'once',count:r.count||2};
  S.steps=(o.steps||[]).map(x=>{
    const t=(x.targets||[]).map(k=>map[k]||k);
    if(x.type==='wait'){const s=newStep('wait');if(x.random){s.mode='random';s.min=x.random.min;s.max=x.random.max}else s.secs=x.seconds??5;return s}
    if(x.type==='fade'){const s=newStep('fade',t);s.fm=typeof x.from==='number'?'set':'current';if(s.fm==='set')s.from=x.from;s.to=x.to??0;s.secs=x.seconds??60;s.wait=x.wait!==false;return s}
    const s=newStep('set',t),c=x.color||{};
    s.power=x.power||'keep';s.bm=x.brightness!=null?'set':'keep';if(x.brightness!=null)s.bri=x.brightness;
    s.color.mode={fixed:'fixed',white:'white',random_choice:'list',random_any:'any'}[c.mode]||'keep';
    if(c.hex)s.color.hex=c.hex;if(c.kelvin)s.color.kelvin=c.kelvin;if(c.hexes)s.color.hexes=c.hexes;
    return s;
  });
  sel=-1;
}
$('#se-fi').addEventListener('change',async e=>{
  const inp=e.target,f=inp.files[0];inp.value='';if(!f)return;
  try{fromJSON(JSON.parse(await f.text()));sync();pal();render();toast('Scene opened')}catch(err){toast(err.message||'Could not read that file.',true)}
});
$('#se-imp').onclick=()=>$('#se-fi').click();
$('#se-new').onclick=()=>{if(S.steps.length&&!confirm('Start a new scene? Unsaved steps will be lost.'))return;S=fresh();sel=-1;sync();render()};
$('#se-exp').onclick=()=>{
  const m=check();if(m){toast(m,true);return}
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([JSON.stringify(build(),null,2)],{type:'application/json'}));
  a.download=((S.name||'scene').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')||'scene')+'.hue-scene.json';
  document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000);toast('Exported '+a.download);
};
$('#se-name').oninput=e=>{S.name=e.target.value;preview()};
$('#se-rm').onchange=e=>{S.repeat.mode=e.target.value;sync();preview()};
$('#se-rc').oninput=e=>{S.repeat.count=Math.max(2,+e.target.value||2);preview()};

/* ---------- editing steps ---------- */
function onEdit(e){
  const el=e.target,st=el.closest('.step');if(!st)return;
  const s=S.steps[+st.dataset.i],d=el.closest('.dur');
  if(d){setP(s,d.dataset.dk,Math.max(0,(parseFloat(d.querySelector('input').value)||0)*parseFloat(d.querySelector('select').value)));preview();return}
  const k=el.dataset.k;if(!k)return;
  const v=el.type==='checkbox'?el.checked:(el.type==='range'||el.type==='number')?+el.value:el.value;
  setP(s,k,v);
  if(el.type==='range'){const o=el.parentNode.querySelector('output');if(o)o.textContent=v+(k.endsWith('kelvin')?' K':'%')}
  if(el.tagName==='SELECT'&&e.type==='change')render();else preview();
}
$('#se-tl').addEventListener('input',onEdit);
$('#se-tl').addEventListener('change',onEdit);
$('#se-tl').addEventListener('click',e=>{
  const st=e.target.closest('.step');if(!st)return;
  const i=+st.dataset.i,s=S.steps[i];let a;
  if(e.target.closest('[data-del]')){S.steps.splice(i,1);sel=-1;render();return}
  if(a=e.target.closest('[data-rt]')){s.t=s.t.filter(k=>k!==a.dataset.rt);render();return}
  if(a=e.target.closest('[data-rs]')){s.color.hexes.splice(+a.dataset.rs,1);render();return}
  if(a=e.target.closest('[data-addc]')){s.color.hexes.push(a.previousElementSibling.value);render();return}
  if(sel!==i){sel=i;document.querySelectorAll('#se .step').forEach(x=>x.classList.toggle('sel',+x.dataset.i===i))}
});
$('#se-pal').addEventListener('click',e=>{
  let a;
  if(a=e.target.closest('[data-drag="target"]')){
    const s=S.steps[sel];
    if(s&&s.t){if(!s.t.includes(a.dataset.key))s.t.push(a.dataset.key)}else{S.steps.push(newStep('set',[a.dataset.key]));sel=S.steps.length-1}
    render();return;
  }
  if(a=e.target.closest('[data-drag="action"]')){S.steps.push(newStep(a.dataset.type,[],a.dataset.preset));sel=S.steps.length-1;render()}
});

/* ---------- drag and drop ---------- */
const main=$('#se-main');
const clr=()=>document.querySelectorAll('#se .over,#se .mb,#se .ma,#se-end.over').forEach(x=>x.classList.remove('over','mb','ma'));
document.addEventListener('dragstart',e=>{
  const el=e.target.closest&&e.target.closest('#se [data-drag]');if(!el)return;
  drag={kind:el.dataset.drag,key:el.dataset.key,type:el.dataset.type,preset:el.dataset.preset,i:+el.dataset.i};
  e.dataTransfer.effectAllowed='copyMove';
  try{e.dataTransfer.setData('text/plain',el.dataset.drag)}catch(_){}
  if(drag.kind==='step'){try{e.dataTransfer.setDragImage(el.closest('.step'),12,12)}catch(_){}}
});
document.addEventListener('dragend',()=>{drag=null;clr()});
main.addEventListener('dragover',e=>{
  if(!drag)return;e.preventDefault();clr();
  const tz=e.target.closest('.tz'),st=e.target.closest('.step');
  if(tz&&drag.kind==='target'){tz.classList.add('over');return}
  if(st&&drag.kind!=='target'){const r=st.getBoundingClientRect();st.classList.add(e.clientY<r.top+r.height/2?'mb':'ma')}
  else if(!st)$('#se-end').classList.add('over');
});
main.addEventListener('dragleave',e=>{if(!main.contains(e.relatedTarget))clr()});
main.addEventListener('drop',e=>{
  if(!drag)return;e.preventDefault();const d=drag;drag=null;clr();
  const st=e.target.closest('.step');let at=S.steps.length,idx=-1;
  if(st){idx=+st.dataset.i;const r=st.getBoundingClientRect();at=e.clientY<r.top+r.height/2?idx:idx+1}
  if(d.kind==='target'){
    if(idx>=0){const s=S.steps[idx];if(s.t&&!s.t.includes(d.key))s.t.push(d.key);sel=idx}
    else{S.steps.splice(at,0,newStep('set',[d.key]));sel=at}
  }else if(d.kind==='action'){S.steps.splice(at,0,newStep(d.type,[],d.preset));sel=at}
  else if(d.kind==='step'){const[m]=S.steps.splice(d.i,1);if(at>d.i)at--;S.steps.splice(at,0,m);sel=at}
  render();
});

/* ---------- preview with the runner ---------- */
let pj=null,pn=0,pt=null,prun=false;
const plog=$('#se-log');
const pset=run=>{prun=run;$('#se-dry').disabled=$('#se-play').disabled=run;$('#se-stop').disabled=!run};
async function ppoll(){
  clearTimeout(pt);
  try{
    const d=await getJSON(`/api/scene-preview/status?job=${pj??''}&since=${pn}`);
    if(pj===null&&!d.running){pj=d.job;pn=d.next;pset(false);return}   // an old finished run: don't bring its log back
    if(d.job!==pj){pj=d.job;plog.textContent=''}
    if(d.lines.length){plog.hidden=false;const near=plog.scrollTop+plog.clientHeight>=plog.scrollHeight-24;plog.textContent+=(plog.textContent?'\\n':'')+d.lines.join('\\n');if(near)plog.scrollTop=plog.scrollHeight}
    pn=d.next;pset(d.running);
    if(d.running)pt=setTimeout(ppoll,700);
  }catch(e){if(prun)pt=setTimeout(ppoll,2000)}
}
async function pstart(mode){
  const m=check();if(m){toast(m,true);return}
  const sc=build();if($('#se-once').checked)sc.repeat={mode:'once'};
  const d=await post('/api/scene-preview/start',{scene:sc,mode,speed:+$('#se-spd').value});
  if(!d)return;
  pj=d.job;pn=0;plog.textContent='';plog.hidden=false;pset(true);ppoll();
}
$('#se-dry').onclick=()=>pstart('dry');
$('#se-play').onclick=()=>{if(confirm('Play this scene on your real lights? They stay as the scene leaves them.'))pstart('play')};
$('#se-stop').onclick=async()=>{if(await post('/api/scene-preview/stop',{}))toast('Stopping…')};

sync();pal();render();ppoll();
})();
{% endraw %}
</script>
{% endif %}
</body>
</html>
"""


GROUP_PANEL_TEMPLATE = MACROS + """
{% set a = g.action %}
{% set is_on = g.get('state', {}).get('any_on', a.get('on')) %}
{% set hexc = xy_to_hex(a.xy[0], a.xy[1], 254) if 'xy' in a else '#ffb14a' %}
<div class="card light {{ 'on' if is_on else 'off' }}" data-url="/api/group/{{ id }}/action" style="--glow:{{ hexc }}">
  <div class="head"><div class="dot">🛋️</div>
    <div class="t"><h2 style="font-size:1.25rem">{{ g.name }}</h2>
      <div class="muted">{{ g.type }}{% if g.get('class') %} · {{ g['class'] }}{% endif %} · {{ on_count }} of {{ total }} lights on</div></div>
    <label class="switch"><input type="checkbox" data-key="on" {{ 'checked' if is_on }}><span></span></label></div>
  <div class="ctrl">{{ controls(a, hexc) }}</div>
</div>
<h3 class="gm-h">Lights in this group</h3>
<div class="grid">
  {% for lid in g.lights %}{% if lid in lights %}{{ light_card(lid, lights[lid], {}, False) }}{% endif %}
  {% else %}<div class="empty">This group has no lights.</div>{% endfor %}
</div>
"""

SCENES_TEMPLATE = """
<h3 class="gm-h">Scenes</h3>
<div class="scene-save">
  <input type="text" id="scene-name" maxlength="32" placeholder="Name for current state, e.g. Movie night" autocomplete="off">
  <button class="btn" type="button" data-save-scene>Save as scene</button>
</div>
<p class="muted" style="margin:8px 0 0;">Saves each light's current on/off, brightness and color as a scene for this group.</p>
<div class="scene-list">
  {% for sid, s in scenes %}
  <div class="scene-row"><b>{{ s.name }}</b>
    <div class="inline"><button class="btn ghost" type="button" data-recall-scene="{{ sid }}">Recall</button>
    {% if is_admin %}<button class="icon-btn" type="button" data-delete-scene="{{ sid }}" title="Delete scene" aria-label="Delete scene">✕</button>{% endif %}</div>
  </div>
  {% else %}<div class="muted">No scenes saved for this group yet.</div>{% endfor %}
</div>
"""


# ==========================================
# 5. View Routes
# ==========================================
def scene_inventory(data):
    """Rooms/zones and lights for the scene editor: v1 ids and names, from the data already fetched.
    Only rooms and zones are offered because those are the groups the v2 API (and so the runner) can drive."""
    return {'lights': {i: {'name': l.get('name', '')} for i, l in data['lights'].items()},
            'groups': {i: {'name': g.get('name', ''), 'type': g.get('type', ''), 'lights': g.get('lights', [])}
                       for i, g in data['groups'].items() if g.get('type') in ('Room', 'Zone')}}


def build_light_groups(groups):
    """{light_id: [(group_id, group_name, group_type), ...]} - rooms first, then by name."""
    m = {}
    ordered = sorted(groups.items(), key=lambda kv: (kv[1].get('type') != 'Room', (kv[1].get('name') or '').lower()))
    for gid, g in ordered:
        for lid in g.get('lights', []):
            m.setdefault(lid, []).append((gid, g.get('name', ''), g.get('type', '')))
    return m


def render(tab, error=None, data=None, user=None, light_groups=None, inventory=None):
    return render_template_string(
        HTML_TEMPLATE, tab=tab, config=config, user=user, light_groups=light_groups or {}, inventory=inventory,
        data=data or {'lights': {}, 'groups': {}, 'sensors': {}, 'schedules': {}},
        error=error, notice=request.args.get('notice'), xy_to_hex=xy_to_hex)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    nxt = request.values.get('next') or '/'
    if request.method == 'POST':
        uname = (request.form.get('username') or '').strip()
        pw = request.form.get('password') or ''
        u = config['users'].get(uname)
        if u and check_password_hash(u['password_hash'], pw):
            session.clear()
            session.permanent = True
            session['user'] = uname
            return redirect(request.form.get('next') or '/')
        error = 'Incorrect username or password'
    return render_template_string(LOGIN_TEMPLATE, error=error, next=nxt)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@app.route('/scene-editor')
def scene_editor_redirect():
    return redirect('/?tab=scenes')  # the editor is now a tab


@app.route('/', methods=['GET'])
def index():
    user = current_user()
    tab = request.args.get('tab') or ('bridges' if user['role'] == 'admin' else 'lights')
    error = request.args.get('error')
    admin_tabs = {'bridges', 'sensors', 'settings', 'users', 'scenes'}
    valid_tabs = {'bridges', 'lights', 'groups', 'sensors', 'settings', 'users', 'scenes', 'account'}

    if tab not in valid_tabs:
        return redirect('/?tab=lights')
    if tab in admin_tabs and user['role'] != 'admin':
        return redirect('/?tab=lights&error=Admins+only')

    data = {'lights': {}, 'groups': {}, 'sensors': {}, 'schedules': {}}
    if tab not in ('bridges', 'account'):
        b = get_bridge()
        if not b and tab != 'users':
            fallback = 'bridges' if user['role'] == 'admin' else 'lights'
            msg = "No active bridge connected. Pair a bridge in the Bridges tab." if user['role'] == 'admin' \
                else "No bridge connected yet. Ask your admin to connect one."
            return render(fallback, msg, user=user)
        try:
            if b and tab in ('lights', 'groups', 'settings', 'scenes'):
                data['lights'] = b.get_light()
            if b and tab in ('lights', 'groups', 'settings', 'users', 'scenes'):
                # 'lights' needs groups too: scope_data uses room membership to
                # filter which lights a non-admin user is allowed to see.
                data['groups'] = b.get_group()
            if b and tab == 'settings':
                data['schedules'] = b.get_schedule()
        except Exception as e:
            error = f"API communication error: {e}"
        if tab in ('lights', 'groups'):
            data = scope_data(user, data)

    light_groups = build_light_groups(data['groups']) if tab in ('lights', 'groups') else {}
    inventory = scene_inventory(data) if tab == 'scenes' else None
    return render(tab, error, data, user=user, light_groups=light_groups, inventory=inventory)


# ==========================================
# 6. API Endpoints
# ==========================================
@app.route('/api/bridge/add', methods=['POST'])
def add_bridge():
    user = current_user()
    if user['role'] != 'admin':
        return redirect('/?tab=lights&error=Admins+only')
    ip = (request.form.get('ip') or '').strip()
    try:
        b = Bridge(ip)
        b.connect()  # raises PhueRegistrationException if link button wasn't pressed
        config['bridges'][ip] = b.username
        config['active_bridge'] = ip
        save_config(config)
        connected_bridges[ip] = b
        return redirect('/?tab=bridges&notice=Bridge+connected')
    except PhueRegistrationException:
        return redirect('/?tab=bridges&error=Registration+failed.+Press+the+link+button+on+the+bridge+first.')
    except Exception as e:
        return redirect(f'/?tab=bridges&error={str(e)}')


@app.route('/api/bridge/set_active', methods=['POST'])
def set_active_bridge():
    user = current_user()
    if user['role'] != 'admin':
        return redirect('/?tab=lights&error=Admins+only')
    config['active_bridge'] = request.form.get('ip')
    save_config(config)
    return redirect('/?tab=bridges')


@app.route('/api/bridge/remove', methods=['POST'])
def remove_bridge():
    user = current_user()
    if user['role'] != 'admin':
        return redirect('/?tab=lights&error=Admins+only')
    ip = request.form.get('ip')
    config['bridges'].pop(ip, None)
    connected_bridges.pop(ip, None)
    if config.get('active_bridge') == ip:
        config['active_bridge'] = next(iter(config['bridges']), None)
    save_config(config)
    return redirect('/?tab=bridges')


def build_action(data):
    """Shared light/group state payload builder."""
    payload = {}
    if 'on' in data:
        payload['on'] = data['on'] in (True, 'true', 'True', '1', 1)
    if 'bri' in data:
        payload['bri'] = max(1, min(254, int(data['bri'])))
    if 'ct' in data:
        payload['ct'] = max(153, min(500, int(data['ct'])))
    if data.get('hex') or data.get('hex_color'):
        payload['xy'] = hex_to_xy(data.get('hex') or data.get('hex_color'))
    return payload


@app.route('/api/light/<id>', methods=['POST'])
@api_endpoint
def set_light(user, b, id):
    if user['role'] != 'admin' and id not in user_light_ids(user, b):
        raise Forbidden('You do not have access to this light')
    hue_ok(b.set_light(int(id), build_action(body()), transitiontime=2))


@app.route('/api/group/create', methods=['POST'])
@api_endpoint
def create_group(user, b):
    require_admin(user)
    hue_ok(b.create_group(request.form.get('name'), request.form.getlist('lights')))


def check_group_access(user, gid):
    if user['role'] != 'admin' and str(gid) not in set(user.get('rooms', [])):
        raise Forbidden('You do not have access to this room')


@app.route('/api/group/<id>/action', methods=['POST'])
@api_endpoint
def action_group(user, b, id):
    check_group_access(user, id)
    hue_ok(b.set_group(int(id), build_action(body()), transitiontime=2))


@app.route('/api/group/<id>/panel', methods=['GET'])
@api_endpoint
def group_panel(user, b, id):
    """HTML fragment for the expanded group window: group controls + every light's live status."""
    check_group_access(user, id)
    g = hue_ok(b.get_group(int(id)))  # must be int: phue treats a str as a group *name*
    lights = b.get_light()
    lids = [str(x) for x in g.get('lights', [])]
    on_count = sum(1 for lid in lids if lights.get(lid, {}).get('state', {}).get('on'))
    html = render_template_string(GROUP_PANEL_TEMPLATE, id=id, g=g, lights=lights,
                                  on_count=on_count, total=len(lids))
    return {'html': html}


# ---- Scenes (per group) ----------------------------------------------------
def group_scene_or_403(b, gid, sid):
    """Fetch a scene and make sure it belongs to this group."""
    sc = hue_ok(b.request('GET', f'/api/{b.username}/scenes/{sid}'))
    if str(sc.get('group')) != str(gid):
        raise Forbidden('That scene does not belong to this group')
    return sc


@app.route('/api/group/<id>/scenes', methods=['GET'])
@api_endpoint
def group_scenes(user, b, id):
    check_group_access(user, id)
    raw = hue_ok(b.request('GET', f'/api/{b.username}/scenes'))
    raw = raw if isinstance(raw, dict) else {}
    scenes = [(sid, sc) for sid, sc in raw.items() if str(sc.get('group')) == str(id)]
    scenes.sort(key=lambda kv: kv[1].get('lastupdated') or '', reverse=True)  # newest first
    html = render_template_string(SCENES_TEMPLATE, scenes=scenes, is_admin=user['role'] == 'admin')
    return {'html': html}


@app.route('/api/group/<id>/scene', methods=['POST'])
@api_endpoint
def save_group_scene(user, b, id):
    """Capture the group's lights as they are right now into a new scene."""
    check_group_access(user, id)
    name = (body().get('name') or '').strip()
    if not name:
        raise ValueError('Scene name is required')
    if len(name) > 32:
        raise ValueError('Scene names can be at most 32 characters')
    g = hue_ok(b.get_group(int(id)))
    lids = [str(x) for x in g.get('lights', [])]
    if not lids:
        raise ValueError('This group has no lights to save')

    payload = {'name': name, 'type': 'GroupScene', 'group': str(id), 'lights': lids, 'recycle': False}
    resp = hue_ok(b.request('POST', f'/api/{b.username}/scenes', payload))
    scene_id = resp[0]['success']['id']
    # Creating a scene records current light states; ask explicitly as well so the
    # result doesn't depend on bridge firmware behaviour. Best-effort.
    try:
        hue_ok(b.request('PUT', f'/api/{b.username}/scenes/{scene_id}', {'storelightstate': True}))
    except Exception as e:
        logging.warning(f"storelightstate failed for scene {scene_id}: {e}")
    return {'scene_id': scene_id}


@app.route('/api/group/<id>/scene/<sid>/recall', methods=['POST'])
@api_endpoint
def recall_group_scene(user, b, id, sid):
    check_group_access(user, id)
    group_scene_or_403(b, id, sid)
    hue_ok(b.set_group(int(id), {'scene': sid}))


@app.route('/api/group/<id>/scene/<sid>/delete', methods=['POST'])
@api_endpoint
def delete_group_scene(user, b, id, sid):
    require_admin(user)
    group_scene_or_403(b, id, sid)
    hue_ok(b.request('DELETE', f'/api/{b.username}/scenes/{sid}'))


@app.route('/api/group/<id>/edit', methods=['POST'])
@api_endpoint
def edit_group(user, b, id):
    require_admin(user)
    payload = {'name': request.form.get('name'), 'lights': [str(x) for x in request.form.getlist('lights')]}
    hue_ok(b.request('PUT', f'/api/{b.username}/groups/{id}', payload))


@app.route('/api/group/<id>/delete', methods=['POST'])
@api_endpoint
def delete_group(user, b, id):
    require_admin(user)
    hue_ok(b.delete_group(int(id)))


# ---- Device discovery (admin only) ---------------------------------------
SCAN_KINDS = ('lights', 'sensors')


def scan_kind(kind):
    if kind not in SCAN_KINDS:
        raise ValueError('Unknown device type')
    return kind


@app.route('/api/bridge/scan', methods=['POST'])
@api_endpoint
def start_scan(user, b):
    """Ask the bridge to open the Zigbee network and search (~40-60s)."""
    require_admin(user)
    kind = scan_kind(body().get('kind', 'lights'))
    # The search call takes no parameters; send {} because phue would otherwise send the text "null".
    hue_ok(b.request('POST', f'/api/{b.username}/{kind}', {}))
    return {'kind': kind}


@app.route('/api/bridge/scan/status', methods=['GET'])
@api_endpoint
def scan_status(user, b):
    require_admin(user)
    kind = scan_kind(request.args.get('kind', 'lights'))
    raw = hue_ok(b.request('GET', f'/api/{b.username}/{kind}/new'))
    raw = raw if isinstance(raw, dict) else {}
    last = raw.get('lastscan', 'none')  # "active" while searching, else a timestamp or "none"
    found = [{'id': k, 'name': v.get('name', '')} for k, v in raw.items()
             if k != 'lastscan' and isinstance(v, dict)]
    found.sort(key=lambda f: int(f['id']) if f['id'].isdigit() else 0)
    return {'scanning': last == 'active', 'lastscan': last, 'found': found}


@app.route('/api/device/<kind>/<id>/rename', methods=['POST'])
@api_endpoint
def rename_device(user, b, kind, id):
    require_admin(user)
    kind = scan_kind(kind)
    name = (body().get('name') or '').strip()
    if not id.isdigit():
        raise ValueError('Invalid device id')
    if not name:
        raise ValueError('Name is required')
    if len(name) > 32:
        raise ValueError('Names can be at most 32 characters')
    hue_ok(b.request('PUT', f'/api/{b.username}/{kind}/{id}', {'name': name}))


# ---- Scene preview: play the editor's scene with hue_scene_runner.py (admin only) ----
RUNNER_FILE = 'hue_scene_runner.py'
PREVIEW_MAX_LINES = 5000
_pv = {'id': 0, 'running': False, 'lines': [], 'code': None, 'mode': None, 'proc': None}
_pv_lock = threading.Lock()


def _pv_pump(proc, job_id, tmp_path):
    """Collect the runner's output line by line and note how it ended."""
    try:
        for line in proc.stdout:
            with _pv_lock:
                if _pv['id'] == job_id:
                    if len(_pv['lines']) < PREVIEW_MAX_LINES:
                        _pv['lines'].append(line.rstrip('\n'))
                    elif len(_pv['lines']) == PREVIEW_MAX_LINES:
                        _pv['lines'].append('... output truncated ...')
        code = proc.wait()
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
    with _pv_lock:
        if _pv['id'] == job_id:
            _pv['lines'].append(f'-- preview finished (exit code {code}) --')
            _pv['code'], _pv['running'] = code, False


def _pv_terminate(proc):
    """Ask the runner to stop (Ctrl-C, so it can say so); kill it if it takes no notice."""
    try:
        if os.name == 'nt':
            proc.terminate()
        else:
            proc.send_signal(signal.SIGINT)
    except OSError:
        return

    def reaper():
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    threading.Thread(target=reaper, daemon=True).start()


def _pv_cleanup():
    proc = _pv['proc']
    if proc and proc.poll() is None:
        proc.kill()


atexit.register(_pv_cleanup)


@app.route('/api/scene-preview/start', methods=['POST'])
@admin_api
def preview_start(user):
    d = body()
    scene, mode = d.get('scene'), d.get('mode')
    if mode not in ('dry', 'play'):
        raise ValueError('mode must be "dry" or "play"')
    if not isinstance(scene, dict) or scene.get('format') != 'hue-scene-sequence' or not scene.get('steps'):
        raise ValueError('That is not a Hue scene export.')
    text = json.dumps(scene)
    if len(text) > 1_000_000:
        raise ValueError('That scene is too large.')
    try:
        speed = float(d.get('speed', 1))
    except (TypeError, ValueError):
        raise ValueError('speed must be a number')
    if not 0.1 <= speed <= 1000:
        raise ValueError('speed must be between 0.1 and 1000')
    here = os.path.dirname(os.path.abspath(__file__))
    runner = os.path.join(here, RUNNER_FILE)
    if not os.path.exists(runner):
        raise ValueError(f'{RUNNER_FILE} was not found next to phadmin.py.')
    with _pv_lock:
        if _pv['running']:
            raise ValueError('A preview is already running. Stop it first.')
        fd, tmp = tempfile.mkstemp(suffix='.hue-scene.json')
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        # The runner reads this same config.json (bridge, key, pinned certificate).
        cmd = [sys.executable, '-u', runner, tmp, '--config', os.path.abspath(CONFIG_FILE)]
        cmd += ['--dry-run'] if mode == 'dry' else ['--speed', str(speed)]
        try:
            proc = subprocess.Popen(cmd, cwd=here, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding='utf-8', errors='replace', bufsize=1,
                                    env=dict(os.environ, PYTHONIOENCODING='utf-8'))
        except OSError as e:
            os.remove(tmp)
            raise ValueError(f'Could not start the runner: {e}')
        _pv.update(id=_pv['id'] + 1, running=True, lines=[], code=None, mode=mode, proc=proc)
        job = _pv['id']
    threading.Thread(target=_pv_pump, args=(proc, job, tmp), daemon=True).start()
    return {'job': job}


@app.route('/api/scene-preview/status', methods=['GET'])
@admin_api
def preview_status(user):
    with _pv_lock:
        try:
            since = int(request.args.get('since', 0))
        except ValueError:
            since = 0
        if request.args.get('job') != str(_pv['id']):
            since = 0  # a different job than the caller knows: send it from the start
        return {'job': _pv['id'], 'running': _pv['running'], 'code': _pv['code'], 'mode': _pv['mode'],
                'lines': _pv['lines'][max(since, 0):], 'next': len(_pv['lines'])}


@app.route('/api/scene-preview/stop', methods=['POST'])
@admin_api
def preview_stop(user):
    with _pv_lock:
        proc = _pv['proc'] if _pv['running'] else None
    if proc:
        _pv_terminate(proc)
    return {'stopping': bool(proc)}


# ---- Sensors (admin only) -------------------------------------------------
@app.route('/api/sensors', methods=['GET'])
@api_endpoint
def list_sensors(user, b):
    require_admin(user)
    contacts, notice = contact_devices(b)
    return {'devices': sort_devices(summarize_sensors(b.get_sensor()) + contacts), 'notice': notice}


UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


@app.route('/api/v2/contact/<rid>', methods=['POST'])
@api_endpoint
def set_contact_enabled(user, b, rid):
    """Enable/disable a contact sensor (whether the bridge uses it in automations)."""
    require_admin(user)
    if not UUID_RE.match(rid):
        raise ValueError('Invalid sensor id')
    enabled = body().get('enabled')
    if not isinstance(enabled, bool):
        raise ValueError('"enabled" must be true or false')
    try:
        v2_request(b.ip, b.username, 'PUT', f'contact/{rid}', {'enabled': enabled})
    except V2Unsupported:
        raise V2Error('That sensor was not found on the bridge')
    with _v2_lock:
        _v2_state.get(b.ip, {}).pop('contacts', None)  # show the change on the next refresh


SENSOR_CONFIG_KEYS = {'on': bool, 'ledindication': bool, 'sensitivity': int, 'tholddark': int, 'tholdoffset': int}


@app.route('/api/sensor/<int:id>/config', methods=['POST'])
@api_endpoint
def set_sensor_config(user, b, id):
    require_admin(user)
    payload = {}
    for k, v in body().items():
        if k in SENSOR_CONFIG_KEYS:
            payload[k] = v if SENSOR_CONFIG_KEYS[k] is bool and isinstance(v, bool) else SENSOR_CONFIG_KEYS[k](v)
    if not payload:
        raise ValueError('No valid sensor settings supplied')
    hue_ok(b.request('PUT', f'/api/{b.username}/sensors/{id}/config', payload))


# ---- Schedules (admin only) -----------------------------------------------
@app.route('/api/schedule/create', methods=['POST'])
@api_endpoint
def create_schedule(user, b):
    require_admin(user)
    name = request.form.get('name')
    time_str = request.form.get('time')  # YYYY-MM-DDTHH:MM
    kind, _, target_id = (request.form.get('target') or '').partition('/')
    state_on = request.form.get('action_state') == 'true'
    if kind not in ('lights', 'groups') or not target_id.isdigit():
        raise ValueError('Invalid schedule target')
    if len(time_str) == 16:
        time_str += ':00'
    endpoint = 'state' if kind == 'lights' else 'action'
    payload = {
        "name": name,
        "description": "Admin UI Schedule",
        "command": {
            "address": f"/api/{b.username}/{kind}/{target_id}/{endpoint}",
            "method": "PUT",
            "body": {"on": state_on}
        },
        "localtime": time_str
    }
    hue_ok(b.request('POST', f'/api/{b.username}/schedules', payload))


@app.route('/api/schedule/delete/<int:id>', methods=['POST'])
@api_endpoint
def delete_schedule(user, b, id):
    require_admin(user)
    hue_ok(b.request('DELETE', f'/api/{b.username}/schedules/{id}'))


# ---- Users -----------------------------------------------------------------
@app.route('/api/user/password', methods=['POST'])
@auth_api
def change_password(user):
    d = body()
    cur, new = d.get('current_password') or '', d.get('new_password') or ''
    record = config['users'][user['username']]
    if not check_password_hash(record['password_hash'], cur):
        raise ValueError('Current password is incorrect')
    if len(new) < 4:
        raise ValueError('New password must be at least 4 characters')
    record['password_hash'] = generate_password_hash(new)
    save_config(config)


@app.route('/api/user/add', methods=['POST'])
@admin_api
def add_user(user):
    d = body()
    uname = (d.get('username') or '').strip()
    pw = d.get('password') or ''
    role = d.get('role') if d.get('role') in ('admin', 'member') else 'member'
    rooms = d.get('rooms') if isinstance(d.get('rooms'), list) else request.form.getlist('rooms')
    if not uname or not pw:
        raise ValueError('Username and password are required')
    if uname in config['users']:
        raise ValueError('That username is already taken')
    config['users'][uname] = {'password_hash': generate_password_hash(pw), 'role': role, 'rooms': list(rooms)}
    save_config(config)


@app.route('/api/user/update/<uname>', methods=['POST'])
@admin_api
def update_user(user, uname):
    if uname not in config['users']:
        raise ValueError('Unknown user')
    d = body()
    rec = config['users'][uname]
    role = d.get('role') if d.get('role') in ('admin', 'member') else rec.get('role', 'member')
    rooms = d.get('rooms') if isinstance(d.get('rooms'), list) else request.form.getlist('rooms')

    admins_left = sum(1 for u in config['users'].values() if u.get('role') == 'admin')
    if rec.get('role') == 'admin' and role != 'admin' and admins_left <= 1:
        raise ValueError('At least one admin account must remain')

    rec['role'] = role
    rec['rooms'] = list(rooms)
    new_pw = d.get('password')
    if new_pw:
        rec['password_hash'] = generate_password_hash(new_pw)
    save_config(config)


@app.route('/api/user/delete/<uname>', methods=['POST'])
@admin_api
def delete_user(user, uname):
    if uname == user['username']:
        raise ValueError('You cannot delete your own account')
    if uname not in config['users']:
        raise ValueError('Unknown user')
    if config['users'][uname].get('role') == 'admin':
        admins_left = sum(1 for u in config['users'].values() if u.get('role') == 'admin')
        if admins_left <= 1:
            raise ValueError('At least one admin account must remain')
    del config['users'][uname]
    save_config(config)


# ==========================================
# 7. Entry Point
# ==========================================
if __name__ == '__main__':
    host = config.get('host', '127.0.0.1')
    port = config.get('port', 8215)
    print(f"[*] Starting Hue Admin on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)
