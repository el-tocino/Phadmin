#!/usr/bin/env python3
"""
hue_scene_runner.py - play a Hue scene sequence through the Hue v2 (CLIP v2) API.

Plays the .hue-scene.json files exported by hue_scene_editor.html. It reads the same
config.json as phadmin.py, so there is nothing new to set up:

    {"active_bridge": "192.168.1.50",
     "bridges":  {"192.168.1.50": "<username>"},     # the v1 username is also the v2 application key
     "v2_pins":  {"192.168.1.50": "<sha256>"}}       # bridge certificate, trusted on first use

    python hue_scene_runner.py movie-night.hue-scene.json
    python hue_scene_runner.py scene.json --dry-run     # show every command, send nothing
    python hue_scene_runner.py scene.json --speed 10    # play 10x faster, to preview
    python hue_scene_runner.py --list                   # rooms, zones and lights on the bridge
    python hue_scene_runner.py scene.json --config /path/to/config.json
    python hue_scene_runner.py scene.json --bridge 192.168.1.50 --key APPLICATION_KEY

Python 3.8+, standard library only. Press Ctrl-C to stop. Fades already sent to the
bridge carry on to their end point; the runner just stops issuing new steps.
"""
import argparse
import colorsys
import hashlib
import http.client
import json
import math
import os
import random
import ssl
import sys
import threading
import time
from contextlib import contextmanager

DEFAULT_CONFIG = 'config.json'
V2_PORT = 443
FADE_MAX_MS = 6_553_500   # longest single transition the bridge accepts (65535 x 100 ms)
LIGHT_GAP = 0.1           # min seconds between commands to one light   (bridge allows ~10/s)
GROUP_GAP = 1.0           # min seconds between commands to one group   (bridge allows ~1/s)


class HueError(RuntimeError):
    """The bridge refused one command. Reported, then the scene carries on."""


class Fatal(RuntimeError):
    """Cannot continue: no bridge, bad key, changed certificate, bad scene file."""


# ----------------------------------------------------------------- config (same file as phadmin.py)
def load_config(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except ValueError as e:
        raise Fatal(f'{path} is not valid JSON: {e}')


def pick_bridge(cfg, ip, key):
    cfg = cfg or {}
    ip = ip or cfg.get('active_bridge')
    if not ip:
        raise Fatal('No bridge configured. Pair one in phadmin (it writes config.json), '
                    'or pass --bridge IP --key APPLICATION_KEY.')
    key = key or (cfg.get('bridges') or {}).get(ip)
    if not key:
        raise Fatal(f'config.json has no username for bridge {ip}. Pair it in phadmin, or pass --key.')
    return ip, key


# ----------------------------------------------------------------- Hue v2 client
class Hue:
    def __init__(self, ip, key, cfg=None, cfg_path=None, dry=False):
        self.ip, self.key, self.dry = ip, key, dry
        self.cfg = cfg if cfg is not None else {}
        self.cfg_path = cfg_path if cfg is not None else None
        self._slots, self._lock = {}, threading.Lock()

    def _check_pin(self, der):
        """The bridge's certificate comes from a private CA, so it is pinned on first use
        (same scheme and same 'v2_pins' entry phadmin uses)."""
        fp = hashlib.sha256(der).hexdigest()
        pins = self.cfg.setdefault('v2_pins', {})
        if self.ip not in pins:
            pins[self.ip] = fp
            self._save_pin(fp)
        elif pins[self.ip] != fp:
            raise Fatal("The bridge's security certificate changed since it was first trusted. "
                        "If you reset the bridge, delete its entry under 'v2_pins' in config.json.")

    def _save_pin(self, fp):
        if not self.cfg_path:
            return
        try:  # update only our key, so concurrent edits by phadmin are not clobbered
            with open(self.cfg_path, encoding='utf-8') as f:
                disk = json.load(f)
            disk.setdefault('v2_pins', {})[self.ip] = fp
            with open(self.cfg_path, 'w', encoding='utf-8') as f:
                json.dump(disk, f, indent=4)
        except (OSError, ValueError):
            pass

    def request(self, method, path, body=None, timeout=10):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(self.ip, V2_PORT, timeout=timeout, context=ctx)
        try:
            try:
                conn.connect()
            except OSError as e:
                raise Fatal(f'Cannot reach the bridge at {self.ip}: {e}')
            self._check_pin(conn.sock.getpeercert(binary_form=True))
            headers, payload = {'hue-application-key': self.key}, None
            if body is not None:
                payload = json.dumps(body)
                headers['Content-Type'] = 'application/json'
            try:
                conn.request(method, f'/clip/v2/resource/{path}', payload, headers)
                res = conn.getresponse()
                raw = res.read()
            except OSError as e:
                raise HueError(f'{method} {path}: {e}')
        finally:
            conn.close()
        if res.status in (401, 403):
            raise Fatal('The bridge rejected the application key for its v2 API.')
        try:
            doc = json.loads(raw or b'{}')
        except ValueError:
            raise HueError(f'{method} {path}: unexpected reply (HTTP {res.status})')
        errors = doc.get('errors') or []
        if res.status >= 400 or errors:
            raise HueError(f'{method} {path}: ' + ('; '.join(e.get('description', 'error') for e in errors)
                                                   or f'HTTP {res.status}'))
        return doc.get('data') or []

    def get(self, path):
        return self.request('GET', path)

    def put(self, rtype, rid, payload):
        """One command, paced to the bridge's limits (also across fade threads)."""
        if self.dry:
            return
        gap = GROUP_GAP if rtype == 'grouped_light' else LIGHT_GAP
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._slots.get(rid, 0) + gap)
            self._slots[rid] = slot
        if slot > now:
            time.sleep(slot - now)
        return self.request('PUT', f'{rtype}/{rid}', payload)


# ----------------------------------------------------------------- colors
def hex_to_xy(h):
    """sRGB hex -> CIE xy (same conversion phadmin uses). The bridge clamps to each lamp's gamut."""
    h = h.lstrip('#')
    r, g, b = (int(h[i:i + 2], 16) / 255.0 for i in (0, 2, 4))
    lin = lambda c: ((c + 0.055) / 1.055) ** 2.4 if c > 0.04045 else c / 12.92
    r, g, b = lin(r), lin(g), lin(b)
    X = r * 0.664511 + g * 0.154324 + b * 0.162028
    Y = r * 0.283881 + g * 0.668433 + b * 0.047685
    Z = r * 0.000088 + g * 0.072310 + b * 0.986039
    s = X + Y + Z
    return (0.0, 0.0) if s == 0 else (X / s, Y / s)


def random_hex():
    r, g, b = colorsys.hsv_to_rgb(random.random(), random.uniform(0.6, 1.0), 1.0)
    return '#%02x%02x%02x' % (round(r * 255), round(g * 255), round(b * 255))


clamp = lambda v, lo, hi: max(lo, min(hi, v))


# ----------------------------------------------------------------- scene file + target resolution
def load_scene(path):
    try:
        with open(path, encoding='utf-8') as f:
            sc = json.load(f)
    except FileNotFoundError:
        raise Fatal(f'Scene file not found: {path}')
    except ValueError as e:
        raise Fatal(f'{path} is not valid JSON: {e}')
    if not isinstance(sc, dict) or sc.get('format') != 'hue-scene-sequence':
        raise Fatal(f'{path} is not a Hue scene export (expected format "hue-scene-sequence").')
    if sc.get('version', 1) > 1:
        raise Fatal('This scene file is from a newer editor than this runner understands.')
    if not sc.get('steps'):
        raise Fatal('The scene has no steps.')
    targets = sc.get('targets') or {}
    for i, s in enumerate(sc['steps'], 1):
        if s.get('type') not in ('set', 'fade', 'wait'):
            raise Fatal(f"Step {i}: unknown step type {s.get('type')!r}.")
        if s['type'] != 'wait':
            if not s.get('targets'):
                raise Fatal(f'Step {i} has no room or light to act on.')
            for k in s['targets']:
                if k not in targets:
                    raise Fatal(f'Step {i} refers to an unknown target {k!r}.')
    return sc


class Target:
    def __init__(self, kind, name, light_ids, gl_id=None):
        self.kind, self.name, self.light_ids, self.gl_id = kind, name, light_ids, gl_id


_name = lambda x: (x.get('metadata') or {}).get('name', '')


def resolve(hue, defs):
    """Match the scene's rooms/lights to the bridge's v2 resources: first by the v1 id the editor
    stored (v2 resources carry it as id_v1), then by name."""
    lights = hue.get('light')
    need_groups = any(d.get('type') == 'group' for d in defs.values())
    groups = (hue.get('room') + hue.get('zone')) if need_groups else []
    out = {}
    for key, d in defs.items():
        is_group = d.get('type') == 'group'
        pool, name, vid = (groups if is_group else lights), d.get('name') or '', d.get('id')
        v1 = ('/groups/' if is_group else '/lights/') + str(vid) if vid else None
        hit = [x for x in pool if v1 and x.get('id_v1') == v1] or \
              [x for x in pool if name and _name(x).lower() == name.lower()]
        label = 'room or zone' if is_group else 'light'
        if not hit:
            raise Fatal(f'No {label} named "{name}"' + (f' (id {vid})' if vid else '') + ' on this bridge. '
                        'Available: ' + ', '.join(sorted(_name(x) for x in pool)[:25]) +
                        '. Run with --list to see them all.')
        if len(hit) > 1:
            raise Fatal(f'"{name}" matches {len(hit)} {label}s; load your rooms and lights from the bridge '
                        'in the editor so each target has an id.')
        x = hit[0]
        if not is_group:
            out[key] = Target('light', _name(x) or name, [x['id']])
            continue
        if x.get('type') == 'room':
            devs = {c['rid'] for c in x.get('children', []) if c.get('rtype') == 'device'}
            ids = [l['id'] for l in lights if (l.get('owner') or {}).get('rid') in devs]
        else:
            ids = [c['rid'] for c in x.get('children', []) if c.get('rtype') == 'light']
        gl = next((s['rid'] for s in x.get('services', []) if s.get('rtype') == 'grouped_light'), None)
        if not gl:
            raise Fatal(f'"{_name(x)}" has no group control on the bridge.')
        out[key] = Target('group', _name(x) or name, ids, gl)
    return out


# ----------------------------------------------------------------- clocks (real, and virtual for --dry-run)
class Clock:
    dry = False

    def __init__(self, speed=1.0):
        self.speed = max(float(speed), 0.001)

    def sleep(self, secs):
        if secs > 0:
            time.sleep(secs / self.speed)

    def stamp(self):
        return time.strftime('%H:%M:%S')


class DryClock:
    """Nothing sleeps; a running total is kept so the plan shows when each step would happen."""
    dry, speed = True, 1.0

    def __init__(self):
        self.t, self.ends = 0.0, []

    def sleep(self, secs):
        self.t += max(secs, 0)

    def stamp(self):
        return f't+{self.t:7.1f}s'

    @contextmanager
    def branch(self):  # a fade that doesn't block the sequence runs alongside it
        t0 = self.t
        try:
            yield
        finally:
            self.ends.append(self.t)
            self.t = t0

    def join(self):
        if self.ends:
            self.t = max([self.t] + self.ends)
            self.ends = []


# ----------------------------------------------------------------- the player
class Runner:
    def __init__(self, hue, scene, targets, clock, verbose=False, log=print):
        self.hue, self.scene, self.targets, self.clock = hue, scene, targets, clock
        self.verbose, self.log = verbose or clock.dry, log
        self.threads, self.fatal = [], None

    def say(self, msg):
        self.log(f'[{self.clock.stamp()}] {msg}')

    def put(self, rtype, rid, payload, label):
        if self.verbose:
            self.say(f'    {label}: {json.dumps(payload, separators=(",", ":"))}')
        try:
            self.hue.put(rtype, rid, payload)
        except HueError as e:
            self.say(f'  ! {label}: {e}')

    def names(self, s):
        return ', '.join(self.targets[k].name for k in s['targets'])

    # --- steps
    def do_wait(self, s):
        if 'random' in s:
            r = s['random']
            secs = random.uniform(r['min'], max(r['min'], r['max']))
            self.say(f'wait {secs:.1f}s (random {r["min"]}-{r["max"]}s)')
        else:
            secs = float(s.get('seconds', 0))
            self.say(f'wait {secs:g}s')
        self.clock.sleep(secs)

    def do_set(self, s):
        p, bits = {}, []
        if s.get('power') in ('on', 'off'):
            p['on'] = {'on': s['power'] == 'on'}
            bits.append(s['power'])
        if s.get('brightness') is not None:
            p['dimming'] = {'brightness': float(clamp(s['brightness'], 0, 100))}
            bits.append(f"{s['brightness']:g}%")
        col, hexv = s.get('color'), None
        if col:
            m = col.get('mode')
            if m == 'fixed':
                hexv = col['hex']
            elif m == 'random_choice' and col.get('hexes'):
                hexv = random.choice(col['hexes'])
            elif m == 'random_any':
                hexv = random_hex()
            elif m == 'white':
                mirek = col.get('mirek') or round(1e6 / col.get('kelvin', 2700))
                p['color_temperature'] = {'mirek': int(clamp(mirek, 153, 500))}
                bits.append(f"white {col.get('kelvin', round(1e6 / mirek))}K")
            if hexv:
                x, y = hex_to_xy(hexv)
                p['color'] = {'xy': {'x': round(x, 4), 'y': round(y, 4)}}
                bits.append(hexv)
        self.say(f'set {self.names(s)}: {", ".join(bits) or "no change"}')
        for k in s['targets']:
            t = self.targets[k]
            needs_lights = 'color' in p or 'color_temperature' in p
            if t.kind == 'light':
                self.put('light', t.light_ids[0], p, t.name)
            elif needs_lights:  # group color goes to each lamp, which works on every firmware
                for lid in t.light_ids:
                    self.put('light', lid, p, f'{t.name}/{lid[:8]}')
            else:
                self.put('grouped_light', t.gl_id, p, t.name)

    def do_fade(self, s):
        to, secs, frm = clamp(float(s['to']), 0, 100), max(float(s.get('seconds', 0)), 0), s.get('from', 'current')
        self.say(f'fade {self.names(s)}: {"current" if frm == "current" else f"{frm:g}%"} -> {to:g}% over {secs:g}s'
                 + ('' if s.get('wait', True) else ' (continues in background)'))
        plans = []
        for k in s['targets']:
            t = self.targets[k]
            rtype, rid = ('light', t.light_ids[0]) if t.kind == 'light' else ('grouped_light', t.gl_id)
            if frm != 'current':
                start = float(frm)
                self.put(rtype, rid, {'on': {'on': True}, 'dimming': {'brightness': start}}, t.name)
            else:
                cur = (self.hue.get(f'{rtype}/{rid}') or [{}])[0]
                is_on, bri = (cur.get('on') or {}).get('on'), (cur.get('dimming') or {}).get('brightness')
                if not is_on:
                    if to <= 0:
                        self.say(f'  {t.name} is already off')
                        continue
                    start = 0.0  # brighten up from off
                    self.put(rtype, rid, {'on': {'on': True}, 'dimming': {'brightness': 0.0}}, t.name)
                elif bri is None:
                    self.say(f'  ! {t.name} cannot be dimmed')
                    continue
                else:
                    start = float(bri)
            plans.append((rtype, rid, start, t.name))
        if not plans:
            return
        loop = lambda: self._fade_loop(plans, to, secs)
        if s.get('wait', True):
            loop()
        elif self.clock.dry:
            with self.clock.branch():
                loop()
        else:
            th = threading.Thread(target=self._guard, args=(loop,), daemon=True)
            th.start()
            self.threads.append(th)

    def _fade_loop(self, plans, to, secs):
        speed = self.clock.speed
        n = max(1, math.ceil(secs * 1000 / speed / FADE_MAX_MS)) if secs > 0 else 1
        seg = secs / n  # fades longer than the bridge allows in one go are chained
        for i in range(1, n + 1):
            for rtype, rid, start, name in plans:
                p = {'dimming': {'brightness': round(start + (to - start) * i / n, 1)}}
                if secs > 0:
                    p['dynamics'] = {'duration': max(1, int(seg * 1000 / speed))}
                self.put(rtype, rid, p, name)
            self.clock.sleep(seg)
        if to <= 0:
            for rtype, rid, _, name in plans:
                self.put(rtype, rid, {'on': {'on': False}}, name)

    def _guard(self, fn):
        try:
            fn()
        except Fatal as e:
            self.fatal = e
        except Exception as e:  # a background fade must never kill the sequence silently
            self.say(f'  ! background fade failed: {e}')

    def join(self):
        if self.clock.dry:
            self.clock.join()
        for th in self.threads:
            th.join()
        self.threads = []
        if self.fatal:
            raise self.fatal

    # --- sequence
    def run(self):
        rep = self.scene.get('repeat') or {}
        mode = rep.get('mode', 'once')
        passes = int(rep.get('count', 2)) if mode == 'count' else (None if mode == 'forever' else 1)
        steps, n = self.scene['steps'], 0
        while passes is None or n < passes:
            n += 1
            started = time.monotonic()
            if passes != 1:
                self.say(f'--- pass {n}' + (f' of {passes}' if passes else ' (Ctrl-C to stop)'))
            for i, s in enumerate(steps, 1):
                getattr(self, 'do_' + s['type'])(s)
            self.join()
            if passes is None and not self.clock.dry and time.monotonic() - started < 1:
                time.sleep(1)  # a loop with no waits must not hammer the bridge
            if self.clock.dry and passes is None:
                break  # --dry-run shows a single pass of an endless scene
        self.say('done')


def list_bridge(hue):
    lights, rooms, zones = hue.get('light'), hue.get('room'), hue.get('zone')
    v1 = lambda x: (x.get('id_v1') or '').split('/')[-1] or '-'
    print('Rooms:');  [print(f'  {v1(x):>3}  {_name(x)}') for x in sorted(rooms, key=_name)]
    print('Zones:');  [print(f'  {v1(x):>3}  {_name(x)}') for x in sorted(zones, key=_name)]
    print('Lights:'); [print(f'  {v1(x):>3}  {_name(x)}') for x in sorted(lights, key=_name)]


def main(argv=None):
    ap = argparse.ArgumentParser(description='Play a Hue scene sequence through the Hue v2 API.')
    ap.add_argument('scene', nargs='?', help='a .hue-scene.json file from hue_scene_editor.html')
    ap.add_argument('--config', default=DEFAULT_CONFIG, help="phadmin's config.json (default: ./config.json)")
    ap.add_argument('--bridge', help='bridge IP (default: active_bridge from the config)')
    ap.add_argument('--key', help='application key (default: the bridge username in the config)')
    ap.add_argument('--dry-run', action='store_true', help='print every command and the timeline; send nothing')
    ap.add_argument('--speed', type=float, default=1.0, help='play N times faster (waits and fades shrink)')
    ap.add_argument('--list', action='store_true', help="list the bridge's rooms, zones and lights, then exit")
    ap.add_argument('-v', '--verbose', action='store_true', help='print each command sent')
    a = ap.parse_args(argv)
    if not a.scene and not a.list:
        ap.error('give a scene file, or use --list')
    try:
        cfg = load_config(a.config)
        ip, key = pick_bridge(cfg, a.bridge, a.key)
        hue = Hue(ip, key, cfg, a.config, dry=a.dry_run)
        if a.list:
            list_bridge(hue)
            return 0
        scene = load_scene(a.scene)
        print(f'Bridge {ip} - scene "{scene.get("name", "untitled")}"' + (' (dry run)' if a.dry_run else ''))
        targets = resolve(hue, scene.get('targets') or {})
        Runner(hue, scene, targets, DryClock() if a.dry_run else Clock(a.speed), a.verbose).run()
        return 0
    except Fatal as e:
        print(f'Error: {e}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nStopped. Fades already sent will finish on the bridge.')
        return 130


if __name__ == '__main__':
    sys.exit(main())
