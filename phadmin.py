import os
import json
import secrets
import logging
import functools
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
    "users": {}      # {"username": {"password_hash":..., "role": "admin"|"member", "rooms": [group_id,...]}}
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

    order = {'presence': 0, 'switch': 1, 'daylight': 2, 'temperature': 3, 'light': 4, 'generic': 5}
    return sorted(devices.values(), key=lambda x: (order.get(x['kind'], 9), x['name'] or ''))


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
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hue Admin</title>
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
.motion-on { color:var(--ok); }
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
</style>
{% endraw %}
</head>
<body>
<header><div class="bar">
  <div class="brand"><i></i> Hue Admin</div>
  <nav>
    {% for key, label, adminOnly in [('lights','Lights',False),('groups','Groups',False),('sensors','Sensors',True),('bridges','Bridges',True),('settings','Schedules',True),('users','Users',True)] %}
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
  <div><h2>Sensors &amp; controls</h2><p class="sub">Motion, temperature, light level, daylight and switches. Live, refreshes every 5 seconds.</p></div>
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
  const icons = { presence: '🚶', temperature: '🌡️', light: '☀️', switch: '🎛️', daylight: '🌅', generic: '📟' };
  let devices = [];
  const ago = iso => {
    if (!iso) return 'never';
    const s = Math.max(0, (Date.now() - new Date(iso + 'Z')) / 1000);
    if (s < 60) return 'just now'; if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago'; return Math.floor(s / 86400) + 'd ago';
  };
  const toggle = (sid, cfg, on) => `<label class="switch"><input type="checkbox" data-sensor="${sid}" data-cfg="${cfg}" ${on ? 'checked' : ''}><span></span></label>`;
  function readingHTML(r) {
    let val = '';
    if (r.kind === 'temperature') {
      val = r.celsius == null ? '–' : (useF ? (r.celsius * 9 / 5 + 32).toFixed(1) + ' °F' : r.celsius.toFixed(1) + ' °C');
    } else if (r.kind === 'light') {
      val = r.lux == null ? '–' : `${r.lux} lx <small>${r.dark ? 'dark' : r.daylight ? 'daylight' : ''}</small>`;
    } else if (r.kind === 'presence') {
      val = `<span class="${r.active ? 'motion-on' : ''}">${r.active ? '● ' : '○ '}${esc(r.value)}</span>`;
    } else val = esc(r.value);
    let html = `<div class="reading"><span class="rl">${esc(r.label)}</span><span class="rv">${val}</span>${r.enabled != null ? toggle(r.id, 'on', r.enabled) : ''}</div>`;
    if (r.settings.sensitivity) {
      const s = r.settings.sensitivity;
      html += `<div class="setting">Sensitivity <input type="range" min="0" max="${s.max}" value="${s.value}" data-sensor="${r.id}" data-cfg="sensitivity"> <b>${s.value}/${s.max}</b></div>`;
    }
    if ('ledindication' in r.settings) html += `<div class="setting">LED indicator ${toggle(r.id, 'ledindication', r.settings.ledindication)}</div>`;
    return html;
  }
  function render() {
    if (!devices.length) { sg.innerHTML = '<div class="empty">No sensors found on this bridge.</div>'; return; }
    sg.innerHTML = devices.map(d => `
      <div class="card"><div class="head"><div class="dot">${icons[d.kind] || icons.generic}</div>
        <div class="t"><h3>${esc(d.name)}</h3><div class="muted">${esc(d.model)} · updated ${ago(d.lastupdated)}</div></div>
        ${d.battery != null ? `<span class="pill ${d.battery < 20 ? 'bad' : 'ok'}">🔋 ${d.battery}%</span>` : ''}
        ${d.reachable === false ? '<span class="pill bad">offline</span>' : ''}</div>
        ${d.readings.map(readingHTML).join('')}</div>`).join('');
  }
  async function refresh() {
    if (document.activeElement && document.activeElement.type === 'range' && sg.contains(document.activeElement)) return;
    try { devices = (await getJSON('/api/sensors')).devices; render(); }
    catch (e) { sg.innerHTML = `<div class="alert">${esc(e.message)}</div>`; }
  }
  sg.addEventListener('change', async e => {
    const el = e.target; if (!el.dataset.sensor) return;
    const v = el.type === 'checkbox' ? el.checked : Number(el.value);
    if (await post(`/api/sensor/${el.dataset.sensor}/config`, { [el.dataset.cfg]: v })) { toast('Saved'); refresh(); }
  });
  $('#unit-btn').onclick = () => { useF = !useF; localStorage.unit = useF ? 'F' : 'C'; render(); };
  refresh(); setInterval(refresh, 5000);
}
</script>
{% endraw %}
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
def build_light_groups(groups):
    """{light_id: [(group_id, group_name, group_type), ...]} - rooms first, then by name."""
    m = {}
    ordered = sorted(groups.items(), key=lambda kv: (kv[1].get('type') != 'Room', (kv[1].get('name') or '').lower()))
    for gid, g in ordered:
        for lid in g.get('lights', []):
            m.setdefault(lid, []).append((gid, g.get('name', ''), g.get('type', '')))
    return m


def render(tab, error=None, data=None, user=None, light_groups=None):
    return render_template_string(
        HTML_TEMPLATE, tab=tab, config=config, user=user, light_groups=light_groups or {},
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


@app.route('/', methods=['GET'])
def index():
    user = current_user()
    tab = request.args.get('tab') or ('bridges' if user['role'] == 'admin' else 'lights')
    error = request.args.get('error')
    admin_tabs = {'bridges', 'sensors', 'settings', 'users'}
    valid_tabs = {'bridges', 'lights', 'groups', 'sensors', 'settings', 'users', 'account'}

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
            if b and tab in ('lights', 'groups', 'settings'):
                data['lights'] = b.get_light()
            if b and tab in ('lights', 'groups', 'settings', 'users'):
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
    return render(tab, error, data, user=user, light_groups=light_groups)


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


# ---- Sensors (admin only) -------------------------------------------------
@app.route('/api/sensors', methods=['GET'])
@api_endpoint
def list_sensors(user, b):
    require_admin(user)
    return {'devices': summarize_sensors(b.get_sensor())}


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
