#!/usr/bin/env python3
"""micropot-web — multi-device management web UI for micropot-c5.

PC-side dashboard that talks to each device's mp_ctl management plane
(HMAC-signed UDP/TCP, same protocol as micropotctl.py) and tails the
JSONL event logs written by log_collector.py.

    python3 tools/micropot_web.py                     # tools/devices.json
    python3 tools/micropot_web.py --bind 0.0.0.0 --token s3cret

Devices are registered in devices.json (see devices.example.json) and can
also be added from the web UI. A PSK written as "${ENV_VAR}" is read from
the environment instead of being stored in plaintext.

Pure standard library; no dependencies, no build step.
"""
import argparse
import csv
import io
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from micropot_proto import CtlError, call

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_TAIL_BYTES = 256 * 1024          # initial log read window
POLL_INTERVAL = 5.0                  # seconds between device polls

# --------------------------------------------------------------------------
# device registry
# --------------------------------------------------------------------------


def _expand_env(value):
    """Expand a single "${VAR}" reference; returns None if unset."""
    if isinstance(value, str):
        m = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", value)
        if m:
            return os.environ.get(m.group(1))
    return value


class DeviceStore:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.devices = {}              # name -> config dict (psk expanded)
        self.runtime = {}              # name -> live state dict
        self.alerts = []               # recent alerts, newest last
        self._alert_id = 0
        self.load()

    def load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = json.load(f)
        except FileNotFoundError:
            raw = {"devices": []}
        except (OSError, json.JSONDecodeError) as e:
            raise SystemExit(f"error: cannot read {self.path}: {e}")
        for d in raw.get("devices", []):
            psk = _expand_env(d.get("psk", ""))
            dev = {
                "name": d["name"],
                "host": d["host"],
                "port": int(d.get("port", 55555)),
                "proto": d.get("proto", "udp"),
                "psk": psk if psk is not None else "",
                "psk_missing": psk is None,
                "logs": d.get("logs", "logs"),
            }
            self.devices[dev["name"]] = dev
            self.runtime[dev["name"]] = {
                "online": False, "status": None, "logstats": None,
                "last_error": None, "last_seen": None, "fails": 0,
            }

    def save(self):
        """Persist the registry. ${ENV} PSKs were expanded in memory, so
        re-emit them in ${} form only if we still know nothing better —
        simplest safe policy: never write expanded PSKs back."""
        out = {"devices": []}
        for d in self.devices.values():
            out["devices"].append({
                "name": d["name"], "host": d["host"], "port": d["port"],
                "proto": d["proto"], "psk": d["psk"], "logs": d["logs"],
            })
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)

    def add(self, cfg):
        with self.lock:
            name = cfg["name"]
            self.devices[name] = {
                "name": name,
                "host": cfg["host"],
                "port": int(cfg.get("port", 55555)),
                "proto": cfg.get("proto", "udp"),
                "psk": cfg.get("psk", ""),
                "psk_missing": False,
                "logs": cfg.get("logs", "logs"),
            }
            self.runtime.setdefault(name, {
                "online": False, "status": None, "logstats": None,
                "last_error": None, "last_seen": None, "fails": 0,
            })
            self.save()

    def remove(self, name):
        with self.lock:
            self.devices.pop(name, None)
            self.runtime.pop(name, None)
            self.save()

    def ctl(self, name, cmd, key=None, value=None, timeout=3.0):
        # Snapshot under the registry lock, then do the network I/O without
        # holding it. The background poller and HTTP handlers call this
        # concurrently; micropot_proto serializes the signed ts counter.
        with self.lock:
            d = self.devices.get(name)
            if d is None:
                raise CtlError("unknown device")
            d = dict(d)
        if d["psk_missing"]:
            raise CtlError("PSK 来自环境变量但未设置（${...}）")
        return call(d["host"], d["port"], d["psk"], cmd, key, value,
                    tcp=(d["proto"] == "tcp"), timeout=timeout)

    def alert(self, level, device, msg):
        self._alert_id += 1
        self.alerts.append({"id": self._alert_id, "ts": time.time(),
                            "level": level, "device": device, "msg": msg})
        del self.alerts[:-20]

    def state(self):
        with self.lock:
            devs = []
            for name, d in self.devices.items():
                rt = self.runtime[name]
                devs.append({
                    "name": name, "host": d["host"], "port": d["port"],
                    "proto": d["proto"], "logs": d["logs"],
                    "online": rt["online"], "status": rt["status"],
                    "logstats": rt["logstats"],
                    "last_error": rt["last_error"],
                    "last_seen": rt["last_seen"],
                })
            return {"devices": devs, "alerts": list(self.alerts),
                    "now": time.time()}


# --------------------------------------------------------------------------
# background poller
# --------------------------------------------------------------------------


def poller(store: DeviceStore, stop: threading.Event):
    while not stop.is_set():
        with store.lock:
            names = list(store.devices)
        for name in names:
            if stop.is_set():
                break
            rt = store.runtime.get(name)
            if rt is None:
                continue
            try:
                result = store.ctl(name, "status", timeout=2.5)
                stats = None
                try:
                    stats = store.ctl(name, "log.stats", timeout=2.5)
                except CtlError:
                    pass
                was_online = rt["online"]
                had_seen = rt["last_seen"] is not None
                had_stats = rt["logstats"] is not None
                prev_dropped = (rt["logstats"] or {}).get("dropped", 0)
                rt.update(online=True, status=result, logstats=stats,
                          last_error=None, last_seen=time.time(), fails=0)
                if not was_online and had_seen:
                    store.alert("ok", name, "设备上线")
                if had_stats and stats and stats.get("dropped", 0) > prev_dropped:
                    store.alert("danger", name,
                                f"日志丢包增加：{prev_dropped} → "
                                f"{stats['dropped']}")
            except CtlError as e:
                # tolerate one flaky poll before declaring the device offline
                fails = rt.get("fails", 0) + 1
                rt["fails"] = fails
                rt["last_error"] = str(e)
                if fails >= 2:
                    if rt["online"]:
                        store.alert("warn", name, "设备离线")
                    rt["online"] = False
        stop.wait(POLL_INTERVAL)


# --------------------------------------------------------------------------
# log files
# --------------------------------------------------------------------------


def _logs_dir(dev):
    """Relative log paths resolve against the current working directory —
    run from the project root so the default "logs" finds the collector's
    output."""
    return dev["logs"]


def list_log_files(dev):
    d = _logs_dir(dev)
    try:
        names = [n for n in os.listdir(d)
                 if n.startswith("micropot-") and n.endswith(".jsonl")]
    except OSError:
        return []
    return sorted(names)


def read_log(dev, fname, after, limit):
    """Read events from byte offset `after` (None = tail window)."""
    if fname not in list_log_files(dev):          # also blocks traversal
        raise CtlError("unknown log file")
    path = os.path.join(_logs_dir(dev), fname)
    size = os.path.getsize(path)
    if after is None:
        after = max(0, size - LOG_TAIL_BYTES)
    events = []
    with open(path, "rb") as f:
        f.seek(after)
        data = f.read(limit)
    offset = after + len(data)
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return {"events": events, "offset": offset, "size": size,
            "eof": offset >= size}


CSV_COLUMNS = ["ts", "boot", "seq", "sid", "evt", "proto", "persona",
               "sip", "sport", "dip", "dport", "data"]


def latest_perf(dev, max_scan=2 * 1024 * 1024):
    """Find the most recent system.perf event in the newest log file.

    The firmware emits it every perf.int_s seconds with psram_free, rssi,
    temp etc. — data the status command doesn't carry."""
    files = list_log_files(dev)
    if not files:
        return None, None
    path = os.path.join(_logs_dir(dev), files[-1])
    size = os.path.getsize(path)
    try:
        with open(path, "rb") as f:
            f.seek(max(0, size - max_scan))
            tail = f.read().decode("utf-8", errors="replace")
    except OSError:
        return None, files[-1]
    best, best_key = None, None
    for line in tail.splitlines():
        if '"perf"' not in line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if evt.get("proto") != "system" or evt.get("evt") != "perf":
            continue
        # ring-buffer replays interleave old boots: freshest = max (boot, ts)
        key = (evt.get("boot") or 0, evt.get("ts") or 0)
        if best_key is None or key > best_key:
            best, best_key = evt, key
    return best, files[-1]


def export_csv(dev, fname):
    """Render a whole log file as CSV (data column holds compact JSON)."""
    if fname not in list_log_files(dev):          # also blocks traversal
        raise CtlError("unknown log file")
    path = os.path.join(_logs_dir(dev), fname)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS,
                       extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            data = evt.get("data")
            evt["data"] = (json.dumps(data, ensure_ascii=False,
                                      separators=(",", ":"))
                           if isinstance(data, (dict, list)) else data)
            w.writerow(evt)
    return buf.getvalue().encode()


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------

STORE: DeviceStore = None
TOKEN = None


class Handler(BaseHTTPRequestHandler):
    server_version = "micropot-web/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):            # quiet
        pass

    # -- helpers ---------------------------------------------------------

    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _err(self, msg, status=400):
        self._send_json({"ok": False, "err": msg}, status)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            raise CtlError("body too large")
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            raise CtlError("invalid JSON body")

    def _authed(self, q=None):
        if not TOKEN:
            return True
        if self.headers.get("X-Token") == TOKEN:
            return True
        # query-param fallback so browser downloads (no headers) can auth
        if q and q.get("token", [None])[0] == TOKEN:
            return True
        return False

    # -- routing ---------------------------------------------------------

    def do_GET(self):
        url = urlparse(self.path)
        path, q = url.path, parse_qs(url.query)
        if path == "/" or path == "/index.html":
            return self._send_html(INDEX_HTML)
        if not self._authed(q):
            return self._err("unauthorized", 401)
        try:
            if path == "/api/state":
                return self._send_json({"ok": True, **STORE.state()})
            m = re.fullmatch(r"/api/dev/([^/]+)/(\w+)", path)
            if m:
                name, op = m.group(1), m.group(2)
                if name not in STORE.devices:
                    return self._err("unknown device", 404)
                dev = STORE.devices[name]
                if op == "status":
                    result = STORE.ctl(name, "status")
                    stats = None
                    try:
                        stats = STORE.ctl(name, "log.stats")
                    except CtlError:
                        pass
                    return self._send_json(
                        {"ok": True, "status": result, "logstats": stats})
                if op == "cfg":
                    return self._send_json(
                        {"ok": True, "cfg": STORE.ctl(name, "list")})
                if op == "perf":
                    evt, fname = latest_perf(dev)
                    return self._send_json(
                        {"ok": True, "perf": evt, "file": fname})
                if op == "logs":
                    files = list_log_files(dev)
                    fname = q.get("file", [files[-1] if files else ""])[0]
                    if not fname:
                        return self._send_json(
                            {"ok": True, "files": [], "file": "",
                             "events": [], "offset": 0, "size": 0,
                             "eof": True})
                    after = q.get("after", [None])[0]
                    after = int(after) if after not in (None, "") else None
                    data = read_log(dev, fname, after,
                                    int(q.get("limit", ["262144"])[0]))
                    return self._send_json(
                        {"ok": True, "files": files, "file": fname, **data})
                if op == "export":
                    files = list_log_files(dev)
                    fname = q.get("file", [files[-1] if files else ""])[0]
                    if fname not in files:
                        return self._err("unknown log file", 404)
                    fmt = q.get("fmt", ["jsonl"])[0]
                    base = f"{name}-{fname.rsplit('.', 1)[0]}"
                    if fmt == "csv":
                        body = export_csv(dev, fname)
                        ctype, dl = "text/csv; charset=utf-8", base + ".csv"
                    elif fmt == "jsonl":
                        with open(os.path.join(_logs_dir(dev), fname),
                                  "rb") as f:
                            body = f.read()
                        ctype, dl = "application/x-ndjson", fname
                    else:
                        return self._err("fmt must be jsonl or csv")
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Content-Disposition",
                                     f'attachment; filename="{dl}"')
                    self.end_headers()
                    self.wfile.write(body)
                    return
            return self._err("not found", 404)
        except CtlError as e:
            return self._err(str(e))
        except (ValueError, OSError) as e:
            return self._err(str(e))

    def do_POST(self):
        url = urlparse(self.path)
        path = url.path
        if not self._authed():
            return self._err("unauthorized", 401)
        try:
            if path == "/api/devices":
                body = self._body()
                for f in ("name", "host"):
                    if not body.get(f):
                        return self._err(f"missing field: {f}")
                if not re.fullmatch(r"[\w.-]{1,32}", body["name"]):
                    return self._err("bad device name")
                if body.get("proto", "udp") not in ("udp", "tcp"):
                    return self._err("proto must be udp or tcp")
                STORE.add(body)
                STORE.alert("info", body["name"], "设备已添加")
                return self._send_json({"ok": True})
            m = re.fullmatch(r"/api/dev/([^/]+)/(\w+)", path)
            if m:
                name, op = m.group(1), m.group(2)
                if name not in STORE.devices:
                    return self._err("unknown device", 404)
                if op == "cmd":
                    body = self._body()
                    cmd = body.get("cmd", "")
                    if cmd not in ("set", "unset", "reset", "reboot",
                                   "log.test"):
                        return self._err("unsupported cmd")
                    result = STORE.ctl(name, cmd, body.get("key"),
                                       body.get("value"))
                    return self._send_json({"ok": True, "result": result})
                if op == "delete":
                    STORE.remove(name)
                    return self._send_json({"ok": True})
            return self._err("not found", 404)
        except CtlError as e:
            return self._err(str(e))

    do_DELETE = do_POST


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MicroPot 控制台</title>
<style>
:root{
  --bg:#0b0e14; --panel:#141926; --panel2:#1a2133; --line:#263049;
  --txt:#dbe4f5; --dim:#8494b3; --accent:#4f8cff; --ok:#34d17b;
  --warn:#f5b544; --danger:#f5534b; --info:#58a6ff;
  --radius:14px; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{background:var(--bg);color:var(--txt);font:14px/1.55 "PingFang SC","Microsoft YaHei",system-ui,sans-serif;overflow:hidden}
button{font:inherit;color:inherit;background:none;border:none;cursor:pointer}
input,select{font:inherit;color:var(--txt);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:6px 10px;outline:none;transition:border-color .2s,box-shadow .2s}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(79,140,255,.18)}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-thumb{background:var(--line);border-radius:4px}

/* ---------- capsule (dynamic island) ---------- */
#capsule{position:fixed;top:14px;left:50%;transform:translateX(-50%);z-index:900;
  background:rgba(20,25,38,.72);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  border:1px solid rgba(120,145,190,.22);border-radius:999px;
  box-shadow:0 8px 32px rgba(0,0,0,.45);overflow:hidden;cursor:pointer;
  transition:width .45s cubic-bezier(.32,.72,.24,1),border-radius .45s cubic-bezier(.32,.72,.24,1),border-color .3s;
  width:340px;user-select:none}
#capsule.expanded{width:420px;border-radius:26px}
#capsule .cap-row{display:flex;align-items:center;justify-content:center;gap:12px;padding:10px 22px;white-space:nowrap}
#cap-time{font-family:var(--mono);font-weight:600;font-variant-numeric:tabular-nums;letter-spacing:.5px}
#cap-date{color:var(--dim);font-size:13px}
.cap-sep{width:1px;height:14px;background:var(--line)}
#cap-devs{font-family:var(--mono);font-size:13px;color:var(--dim)}
#cap-devs b{color:var(--ok);font-weight:600}
#cap-brief{display:none;font-size:12px;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#capsule.alerting #cap-brief{display:inline-block}
#cap-expand{max-height:0;opacity:0;transition:max-height .4s ease,opacity .3s ease}
#capsule.expanded #cap-expand{max-height:280px;opacity:1;overflow-y:auto}
.cap-dev{display:flex;align-items:center;gap:10px;padding:9px 22px;border-top:1px solid rgba(120,145,190,.12);transition:background .2s}
.cap-dev:hover{background:rgba(79,140,255,.08)}
.cap-dev .nm{flex:1}
.cap-dev .ip{font-family:var(--mono);font-size:12px;color:var(--dim)}
@keyframes capPulse{0%,100%{box-shadow:0 8px 32px rgba(0,0,0,.45)}50%{box-shadow:0 0 0 6px var(--pulse,rgba(245,83,75,.35)),0 8px 32px rgba(0,0,0,.45)}}
#capsule.pulse{animation:capPulse 1s ease 3}
#capsule.pulse.danger{--pulse:rgba(245,83,75,.4);border-color:var(--danger)}
#capsule.pulse.warn{--pulse:rgba(245,181,68,.4);border-color:var(--warn)}
#capsule.pulse.ok{--pulse:rgba(52,209,123,.4);border-color:var(--ok)}

/* ---------- sidebar ---------- */
#sidebar{position:fixed;left:0;top:0;bottom:0;width:230px;background:var(--panel);
  border-right:1px solid var(--line);display:flex;flex-direction:column;z-index:800}
#logo{padding:76px 20px 16px;font-size:17px;font-weight:700;letter-spacing:.4px}
#logo span{color:var(--accent)}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 20px;color:var(--dim);
  cursor:pointer;border-left:3px solid transparent;transition:all .2s;font-size:13.5px}
.nav-item:hover{color:var(--txt);background:rgba(79,140,255,.06)}
.nav-item.active{color:var(--txt);background:rgba(79,140,255,.12);border-left-color:var(--accent)}
.nav-item .nm{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nav-item .ip{font-family:var(--mono);font-size:11px;color:var(--dim)}
.dot{width:8px;height:8px;border-radius:50%;flex:none;background:#3a4a6e}
.dot.on{background:var(--ok);box-shadow:0 0 8px rgba(52,209,123,.7);animation:breathe 2.4s ease-in-out infinite}
.dot.off{background:#4a5878}
@keyframes breathe{0%,100%{opacity:1}50%{opacity:.45}}
#side-add{margin:auto 16px 16px;padding:10px;border:1px dashed var(--line);border-radius:10px;
  color:var(--dim);text-align:center;cursor:pointer;transition:all .2s;font-size:13px}
#side-add:hover{border-color:var(--accent);color:var(--accent)}

/* ---------- main ---------- */
#main{position:fixed;left:230px;right:0;top:0;bottom:0;overflow-y:auto;padding:84px 32px 40px}
.view{animation:viewIn .35s cubic-bezier(.25,.8,.3,1)}
@keyframes viewIn{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
h1{font-size:20px;font-weight:700;margin-bottom:4px}
.sub{color:var(--dim);font-size:13px;margin-bottom:22px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:18px;transition:transform .25s ease,box-shadow .25s ease,border-color .25s}
.card:hover{transform:translateY(-3px);box-shadow:0 10px 26px rgba(0,0,0,.35);border-color:#324063}
.card .t{font-size:12.5px;color:var(--dim);margin-bottom:8px;display:flex;align-items:center;gap:7px}
.card .v{font-family:var(--mono);font-size:22px;font-weight:600;font-variant-numeric:tabular-nums}
.card .s{font-size:12px;color:var(--dim);margin-top:6px;font-family:var(--mono)}
.devcard{cursor:pointer;position:relative}
.devcard .hd{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.devcard .hd b{font-size:15.5px}
.devcard.offline{opacity:.62}
.devcard .kv{display:flex;justify-content:space-between;font-size:12.5px;color:var(--dim);padding:3px 0}
.devcard .kv span:last-child{font-family:var(--mono);color:var(--txt)}
.del{position:absolute;top:10px;right:12px;color:var(--dim);opacity:0;transition:opacity .2s;font-size:15px;padding:2px 6px;border-radius:6px}
.devcard:hover .del{opacity:.7}
.del:hover{color:var(--danger);background:rgba(245,83,75,.12)}

/* ---------- tabs ---------- */
.tabs{display:flex;gap:6px;margin-bottom:22px;background:var(--panel);border:1px solid var(--line);
  border-radius:12px;padding:5px;width:max-content}
.tab{padding:8px 20px;border-radius:9px;color:var(--dim);cursor:pointer;font-size:13.5px;transition:all .22s}
.tab:hover{color:var(--txt)}
.tab.active{background:var(--accent);color:#fff;box-shadow:0 3px 10px rgba(79,140,255,.35)}

/* ---------- tables ---------- */
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--dim);font-weight:500;padding:9px 12px;border-bottom:1px solid var(--line);
  position:sticky;top:0;background:var(--panel);z-index:2}
td{padding:9px 12px;border-bottom:1px solid rgba(38,48,73,.5);vertical-align:middle}
tbody tr{transition:background .15s}
tbody tr:hover{background:rgba(79,140,255,.05)}
.mono{font-family:var(--mono);font-size:12.5px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden}
.panel .ph{padding:14px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.panel .ph b{font-size:14.5px}
.chip{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11.5px;font-family:var(--mono);
  background:rgba(79,140,255,.14);color:var(--info);border:1px solid rgba(79,140,255,.3)}
.chip.hot{background:rgba(245,181,68,.14);color:var(--warn);border-color:rgba(245,181,68,.35)}

/* ---------- config ---------- */
.info-ic{display:inline-flex;width:18px;height:18px;border-radius:50%;background:rgba(88,166,255,.16);
  color:var(--info);font-size:11px;align-items:center;justify-content:center;cursor:help;font-style:italic;flex:none}
.tag{font-size:10.5px;padding:1px 7px;border-radius:5px;margin-left:6px;font-family:var(--mono);white-space:nowrap}
.tag.rb{background:rgba(245,181,68,.15);color:var(--warn)}
.tag.wr{background:rgba(245,83,75,.15);color:var(--danger)}
.rowbtns{white-space:nowrap;text-align:right}
.btn{padding:6px 16px;border-radius:9px;font-size:13px;transition:all .2s;border:1px solid var(--line);color:var(--dim)}
.btn:hover{color:var(--txt);border-color:#3b4a6e}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover{filter:brightness(1.12)}
.btn.warn{background:rgba(245,181,68,.15);border-color:var(--warn);color:var(--warn)}
.btn.danger{background:rgba(245,83,75,.15);border-color:var(--danger);color:var(--danger)}
.btn.sm{padding:4px 12px;font-size:12px}
.btn:disabled{opacity:.4;cursor:not-allowed}
.switch{position:relative;width:40px;height:22px;background:#2a3550;border-radius:999px;cursor:pointer;transition:background .25s;flex:none}
.switch::after{content:"";position:absolute;top:3px;left:3px;width:16px;height:16px;border-radius:50%;background:#8fa0c4;transition:all .25s cubic-bezier(.3,1.4,.5,1)}
.switch.on{background:var(--ok)}
.switch.on::after{left:21px;background:#fff}
.warnbar{display:flex;gap:10px;align-items:flex-start;background:rgba(245,181,68,.1);border:1px solid rgba(245,181,68,.35);
  color:var(--warn);border-radius:10px;padding:10px 14px;font-size:12.5px;margin-bottom:14px;animation:viewIn .3s}
.tooltip{position:fixed;z-index:1000;max-width:300px;background:#0f1420;border:1px solid var(--line);border-radius:10px;
  padding:10px 13px;font-size:12.5px;color:var(--txt);box-shadow:0 10px 30px rgba(0,0,0,.5);pointer-events:none;
  animation:viewIn .18s}
.tooltip .tk{font-family:var(--mono);color:var(--accent);font-size:11.5px;margin-bottom:4px}

/* ---------- toasts ---------- */
#toasts{position:fixed;right:22px;bottom:22px;z-index:950;display:flex;flex-direction:column;gap:10px;width:330px}
.toast{background:var(--panel2);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:12px;
  padding:12px 14px 14px;box-shadow:0 12px 32px rgba(0,0,0,.5);position:relative;overflow:hidden;
  animation:toastIn .38s cubic-bezier(.25,1.1,.4,1);cursor:pointer}
.toast.out{animation:toastOut .3s forwards}
@keyframes toastIn{from{opacity:0;transform:translateX(60px) scale(.95)}to{opacity:1;transform:none}}
@keyframes toastOut{to{opacity:0;transform:translateX(60px) scale(.92);height:0;padding:0 14px;margin:0}}
.toast.ok{border-left-color:var(--ok)} .toast.warn{border-left-color:var(--warn)}
.toast.danger{border-left-color:var(--danger)} .toast.info{border-left-color:var(--info)}
.toast .tt{font-size:13px;font-weight:600;display:flex;gap:8px;align-items:center}
.toast .tm{font-size:12px;color:var(--dim);margin-top:3px;word-break:break-all}
.toast .bar{position:absolute;left:0;bottom:0;height:2.5px;background:currentColor;opacity:.55;
  animation:tbar linear forwards;width:100%}
.toast:hover .bar{animation-play-state:paused}
.toast.ok .bar{color:var(--ok)} .toast.warn .bar{color:var(--warn)}
.toast.info .bar{color:var(--info)} .toast.danger .bar{color:var(--danger)}
@keyframes tbar{from{width:100%}to{width:0}}

/* ---------- modal ---------- */
#modal-root:empty{display:none}
.overlay{position:fixed;inset:0;background:rgba(4,7,12,.6);backdrop-filter:blur(3px);z-index:960;
  display:flex;align-items:center;justify-content:center;animation:fadeIn .22s}
@keyframes fadeIn{from{opacity:0}}
.modal{width:440px;max-width:92vw;background:var(--panel2);border:1px solid var(--line);border-radius:18px;
  padding:24px;box-shadow:0 24px 60px rgba(0,0,0,.6);animation:modalIn .32s cubic-bezier(.3,1.25,.4,1)}
@keyframes modalIn{from{opacity:0;transform:scale(.92) translateY(12px)}to{opacity:1;transform:none}}
.modal.warn{border-color:rgba(245,181,68,.5)}
.modal.danger{border-color:rgba(245,83,75,.55)}
.modal h3{font-size:16px;margin-bottom:10px;display:flex;gap:9px;align-items:center}
.modal .mb{font-size:13px;color:var(--dim);margin-bottom:16px;line-height:1.7}
.modal .mb code{font-family:var(--mono);color:var(--warn);background:rgba(245,181,68,.1);padding:1px 6px;border-radius:5px}
.modal .mf{display:flex;flex-direction:column;gap:10px;margin-bottom:16px}
.modal .mf label{font-size:12px;color:var(--dim)}
.modal .mrow{display:flex;justify-content:flex-end;gap:10px}
.confirm-word{font-family:var(--mono);color:var(--danger);font-weight:700}

/* ---------- login ---------- */
#login{position:fixed;inset:0;background:var(--bg);z-index:990;display:none;align-items:center;justify-content:center}
#login.show{display:flex}
#login .box{width:340px;background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:30px;text-align:center}

.flash{animation:flashCell 1.2s ease}
@keyframes flashCell{0%{background:rgba(52,209,123,.22)}100%{background:transparent}}
.empty{padding:60px 0;text-align:center;color:var(--dim)}
.evt-kind{font-family:var(--mono);font-size:12px}
.k-login{color:var(--warn)} .k-danger{color:var(--danger)} .k-conn{color:var(--info)} .k-cmd{color:#c792ea}
@media(max-width:860px){#sidebar{display:none}#main{left:0;padding:84px 16px 30px}}
</style>
</head>
<body>

<div id="capsule">
  <div class="cap-row" id="cap-row">
    <span id="cap-time">--:--:--</span>
    <span class="cap-sep"></span>
    <span id="cap-date">—</span>
    <span class="cap-sep"></span>
    <span id="cap-devs">● <b>0</b>/0</span>
    <span id="cap-brief"></span>
  </div>
  <div id="cap-expand"></div>
</div>

<aside id="sidebar">
  <div id="logo">Micro<span>Pot</span> 控制台</div>
  <div id="nav"></div>
  <div id="side-add">＋ 添加设备</div>
</aside>

<main id="main"></main>
<div id="toasts"></div>
<div id="modal-root"></div>

<div id="login">
  <div class="box">
    <h3 style="margin-bottom:8px">🔒 需要访问口令</h3>
    <p class="sub" style="margin-bottom:16px">服务端以 --token 启动</p>
    <input id="login-token" type="password" placeholder="访问口令" style="width:100%;margin-bottom:14px">
    <button class="btn primary" style="width:100%" onclick="doLogin()">进入</button>
  </div>
</div>

<script>
"use strict";
/* ================= state ================= */
const S = {
  token: sessionStorage.getItem("mpw_token") || "",
  devices: [], alerts: [], seenAlert: 0,
  view: {kind: "overview"},
  cfg: {},                 // name -> {key: value}
  dirty: {},               // name -> {key: value}
  log: {file: "", offset: null, events: [], tail: true, fKind: "", fSrc: ""},
  timers: {},
};
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

/* ================= api ================= */
async function api(path, opts = {}) {
  const r = await fetch(path, {
    ...opts,
    headers: {"X-Token": S.token,
              ...(opts.body ? {"Content-Type": "application/json"} : {})},
  });
  if (r.status === 401) { $("#login").classList.add("show"); throw new Error("unauthorized"); }
  const obj = await r.json().catch(() => ({ok: false, err: "bad response"}));
  if (!obj.ok) throw new Error(obj.err || "request failed");
  return obj;
}
function doLogin() {
  S.token = $("#login-token").value;
  sessionStorage.setItem("mpw_token", S.token);
  $("#login").classList.remove("show");
  loadState();
}

/* ================= toasts ================= */
const T_ICON = {ok: "✅", warn: "⚠️", danger: "🛑", info: "ℹ️"};
function toast(level, title, msg, {sticky = false, ms = 5200} = {}) {
  if (level === "danger") sticky = true;
  const el = document.createElement("div");
  el.className = "toast " + level;
  el.innerHTML = `<div class="tt">${T_ICON[level]||"ℹ️"} ${esc(title)}</div>
    ${msg ? `<div class="tm">${esc(msg)}</div>` : ""}
    ${sticky ? "" : `<div class="bar" style="animation-duration:${ms}ms"></div>`}`;
  el.onclick = () => dismiss();
  $("#toasts").appendChild(el);
  let to = null;
  const dismiss = () => { clearTimeout(to); el.classList.add("out");
    setTimeout(() => el.remove(), 300); };
  if (!sticky) to = setTimeout(dismiss, ms);
  while ($("#toasts").children.length > 6)
    $("#toasts").firstChild.remove();
}

/* ================= modal ================= */
function modal({title, body, level = "", confirmText = "确认", fields = null,
                requireText = null, onConfirm}) {
  const root = $("#modal-root");
  root.innerHTML = `<div class="overlay">
    <div class="modal ${level}">
      <h3>${level==="danger"?"🛑":level==="warn"?"⚠️":"ℹ️"} ${esc(title)}</h3>
      <div class="mb">${body}</div>
      ${fields ? `<div class="mf">${fields.map(f => `
        <label>${esc(f.label)}
        <input data-f="${esc(f.key)}" type="${f.type||"text"}"
               placeholder="${esc(f.ph||"")}" value="${esc(f.value||"")}">
        </label>`).join("")}</div>` : ""}
      ${requireText ? `<div class="mf"><label>
        请输入设备名 <span class="confirm-word">${esc(requireText)}</span> 以确认
        <input id="m-confirm-word" autocomplete="off"></label></div>` : ""}
      <div class="mrow">
        <button class="btn" id="m-cancel">取消</button>
        <button class="btn ${level==="danger"?"danger":level==="warn"?"warn":"primary"}"
                id="m-ok" ${requireText?"disabled":""}>${esc(confirmText)}</button>
      </div>
    </div></div>`;
  const close = () => root.innerHTML = "";
  $("#m-cancel").onclick = close;
  root.querySelector(".overlay").onclick = e => {
    if (e.target.classList.contains("overlay")) close(); };
  if (requireText)
    $("#m-confirm-word").oninput = e =>
      $("#m-ok").disabled = e.target.value.trim() !== requireText;
  $("#m-ok").onclick = async () => {
    const vals = {};
    root.querySelectorAll("[data-f]").forEach(i => vals[i.dataset.f] = i.value.trim());
    close();
    if (onConfirm) onConfirm(vals);
  };
}

/* ================= config metadata ================= */
const KEY_INFO = {
  "wifi.ssid":   {d: "要连接的 WiFi 网络名（SSID）", warn: 1, rb: 1},
  "wifi.pass":   {d: "WiFi 密码。设备端保密存储，页面不显示原值，输入即覆盖", sec: 1, warn: 1, rb: 1},
  "net.mac":     {d: "MAC 地址欺骗，格式 aa:bb:cc:dd:ee:ff；留空用芯片默认", t: "mac", warn: 1, rb: 1},
  "net.hostname":{d: "DHCP 主机名，留空用默认", rb: 1},
  "log.host":    {d: "日志采集器（log_collector.py）的 IP", t: "ip", rb: 1},
  "log.port":    {d: "日志采集器端口，需与 log_collector.py --port 一致", t: "u32", rb: 1},
  "log.tcp":     {d: "日志走 TCP（可靠）还是 UDP（默认，可能丢包）", t: "bool", rb: 1},
  "log.console": {d: "事件同时输出到串口控制台（调试用）", t: "bool"},
  "log.queue":   {d: "事件队列长度（8–128）。队列满会丢事件并计入 log.dropped", t: "u32", rb: 1},
  "log.ring":    {d: "离线时把事件溢写到 SPIFFS 环形缓冲，采集器恢复后补发", t: "bool", rb: 1},
  "stack.tcbs":  {d: "s419 并发 TCP 控制块数（16–256）。PSRAM 占用 ≈ tcbs × (rx_cap+tx_cap)", t: "u32", rb: 1},
  "stack.synrecv":{d: "半连接（SYN_RECV）队列上限（8–128）", t: "u32", rb: 1},
  "stack.rx_cap":{d: "每连接接收环（KiB，1–16）。塑造通告窗口增长，属于 nmap 指纹，勿随意改", t: "u32", warn: 1, rb: 1},
  "stack.tx_cap":{d: "每连接发送环（KiB，4–64）", t: "u32", rb: 1},
  "sess.idle_s": {d: "空闲会话回收秒数，0 = 不回收（同真实 sshd）", t: "u32"},
  "ssh.preauth_max":{d: "SSH 并发 KEX 上限（1–8），防止暴力破解耗尽内存", t: "u32"},
  "cred.root":   {d: "蜜罐 root 口令（攻击者视角的「正确」密码）。保密存储，输入即覆盖", sec: 1},
  "cred.admin":  {d: "蜜罐 admin 口令。保密存储，输入即覆盖", sec: 1},
  "mgmt.ip":     {d: "管理平面专用地址——本网页正是通过它控制设备，改错会失联！", t: "ip", warn: 1, rb: 1},
  "ctl.port":    {d: "控制通道端口（默认 55555）。改动后需同步 devices.json", t: "u32", warn: 1, rb: 1},
  "ctl.psk":     {d: "控制通道 HMAC 预共享密钥。修改后必须同步更新 devices.json，否则失联！", sec: 1, warn: 1},
  "ctl.admin":   {d: "允许的管理来源 IP（ACL），0.0.0.0 为不限制", t: "ip", warn: 1},
  "perf.int_s":  {d: "性能采样周期（秒）", t: "u32"},
  "perf.heap_kb":{d: "性能堆采样窗口（KB）", t: "u32"},
  "probe.enabled":{d: "主动探测开关（周期性心跳）", t: "bool"},
  "probe.int_s": {d: "探测间隔（秒，5–3600）", t: "u32"},
  "persona":     {d: "主 persona（品牌人格），决定全部蜜罐服务的伪装身份", warn: 1, rb: 1},
  "port.telnet": {d: "Telnet 蜜罐监听端口", t: "u32", warn: 1, rb: 1},
  "port.http":   {d: "HTTP 蜜罐监听端口", t: "u32", warn: 1, rb: 1},
  "port.ssh":    {d: "SSH 蜜罐监听端口", t: "u32", warn: 1, rb: 1},
  "port.ftp":    {d: "FTP 蜜罐监听端口", t: "u32", warn: 1, rb: 1},
};
function keyInfo(k) {
  if (KEY_INFO[k]) return KEY_INFO[k];
  let m;
  if ((m = /^vdev\d+\.ip$/.exec(k)))
    return {d: "虚拟设备 IP 地址", t: "ip", warn: 1, rb: 1};
  if (/^vdev\d+\.persona$/.test(k))
    return {d: "该虚拟设备使用的 persona（品牌人格）", warn: 1, rb: 1};
  return {d: "未收录的配置键，含义请查阅 docs/ 与组件源码"};
}
function keyType(k, v) {
  const t = keyInfo(k).t;
  if (t) return t;
  if (v === "true" || v === "false") return "bool";
  if (/^\d+$/.test(v)) return "u32";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "ip";
  return "str";
}

/* ================= capsule ================= */
function tickClock() {
  const n = new Date(), p = x => String(x).padStart(2, "0");
  $("#cap-time").textContent =
    `${p(n.getHours())}:${p(n.getMinutes())}:${p(n.getSeconds())}`;
  const wk = "日一二三四五六"[n.getDay()];
  $("#cap-date").textContent = `${n.getMonth()+1}月${n.getDate()}日 周${wk}`;
}
setInterval(tickClock, 1000); tickClock();

$("#cap-row").addEventListener("click", () =>
  $("#capsule").classList.toggle("expanded"));

function renderCapsule() {
  const on = S.devices.filter(d => d.online).length;
  $("#cap-devs").innerHTML = `● <b>${on}</b>/${S.devices.length}`;
  $("#cap-expand").innerHTML = S.devices.map(d => `
    <div class="cap-dev" onclick="event.stopPropagation();openDevice('${esc(d.name)}')">
      <span class="dot ${d.online ? "on" : "off"}"></span>
      <span class="nm">${esc(d.name)}</span>
      <span class="ip">${esc(d.host)}</span>
    </div>`).join("") ||
    `<div class="cap-dev"><span class="nm" style="color:var(--dim)">暂无设备，点左下角添加</span></div>`;
}
let pulseTimer = null;
function pulseCapsule(level, brief) {
  const c = $("#capsule");
  c.classList.remove("pulse", "ok", "warn", "danger");
  void c.offsetWidth;                        // restart animation
  c.classList.add("pulse", level, "alerting");
  $("#cap-brief").textContent = brief;
  $("#cap-brief").style.color = `var(--${level})`;
  clearTimeout(pulseTimer);
  pulseTimer = setTimeout(() =>
    c.classList.remove("pulse", level, "alerting"), 4000);
}

/* ================= state polling ================= */
async function loadState() {
  try {
    const st = await api("/api/state");
    S.devices = st.devices;
    for (const a of st.alerts) {
      if (a.id > S.seenAlert) {
        S.seenAlert = a.id;
        toast(a.level === "ok" ? "ok" : a.level, a.device, a.msg);
        pulseCapsule(a.level === "ok" ? "ok" : a.level, a.msg);
      }
    }
    renderCapsule(); renderNav();
    if (S.view.kind === "overview") renderOverview();
    if (S.view.kind === "device" && S.view.tab === "status") renderDevStatus();
  } catch (e) { if (e.message !== "unauthorized") console.warn(e); }
}

/* ================= nav ================= */
function renderNav() {
  const v = S.view;
  $("#nav").innerHTML = `
    <div class="nav-item ${v.kind==="overview"?"active":""}" onclick="go({kind:'overview'})">
      <span>📊</span><span class="nm">全部概览</span></div>
    <div style="padding:12px 20px 6px;font-size:11px;color:var(--dim)">设备</div>
    ${S.devices.map(d => `
      <div class="nav-item ${v.kind==="device"&&v.name===d.name?"active":""}"
           onclick="openDevice('${esc(d.name)}')">
        <span class="dot ${d.online?"on":"off"}"></span>
        <span class="nm">${esc(d.name)}</span>
        <span class="ip">${esc(d.host)}</span>
      </div>`).join("")}`;
}
$("#side-add").onclick = () => modal({
  title: "添加设备",
  body: "注册一台蜜罐设备的管理端点。PSK 与设备 <code>ctl.psk</code> 一致。",
  fields: [
    {key: "name", label: "名称（唯一标识）", ph: "hik-cam"},
    {key: "host", label: "管理地址（mgmt.ip）", ph: "192.168.1.15"},
    {key: "port", label: "控制端口", value: "55555"},
    {key: "proto", label: "协议 udp / tcp", value: "udp"},
    {key: "psk", label: "PSK 预共享密钥", type: "password"},
    {key: "logs", label: "日志目录（相对项目根）", value: "logs"},
  ],
  confirmText: "添加",
  onConfirm: async v => {
    try {
      await api("/api/devices", {method: "POST", body: JSON.stringify(v)});
      toast("ok", "设备已添加", v.name);
      loadState();
    } catch (e) { toast("danger", "添加失败", e.message); }
  },
});

/* ================= routing ================= */
function stopTimers() {
  Object.values(S.timers).forEach(clearInterval);
  S.timers = {};
}
function go(v) { stopTimers(); S.view = v; renderNav(); renderMain(); }
function openDevice(name) { go({kind: "device", name, tab: "status"}); }

function renderMain() {
  if (S.view.kind === "overview") return renderOverview(true);
  renderDevice();
}

/* ================= overview ================= */
function renderOverview(full) {
  const m = $("#main");
  if (full || !m.querySelector(".cards"))
    m.innerHTML = `<div class="view"><h1>全部概览</h1>
      <div class="sub">${S.devices.length} 台注册设备 · 每 5 秒自动刷新</div>
      <div class="cards" id="ov-cards"></div></div>`;
  const box = $("#ov-cards");
  if (!S.devices.length) {
    box.innerHTML = `<div class="empty">还没有设备。<br>点击左侧「＋ 添加设备」注册第一台蜜罐。</div>`;
    return;
  }
  box.innerHTML = S.devices.map(d => {
    const s = d.status || {}, lg = d.logstats || {};
    return `<div class="card devcard ${d.online?"":"offline"}"
                 onclick="openDevice('${esc(d.name)}')">
      <span class="del" title="移除设备"
        onclick="event.stopPropagation();delDevice('${esc(d.name)}')">✕</span>
      <div class="hd"><span class="dot ${d.online?"on":"off"}"></span>
        <b>${esc(d.name)}</b>
        <span class="chip">${d.online ? "在线" : "离线"}</span></div>
      ${d.online ? `
      <div class="kv"><span>管理地址</span><span>${esc(d.host)}</span></div>
      <div class="kv"><span>运行时间</span><span>${fmtUp(s.uptime_s)}</span></div>
      <div class="kv"><span>活跃会话</span><span>${s.sessions_active ?? "—"}</span></div>
      <div class="kv"><span>空闲堆</span><span>${fmtKB(s.heap_free)}</span></div>
      <div class="kv"><span>日志丢包</span><span>${lg.dropped ?? "—"}</span></div>`
      : `<div class="kv"><span>管理地址</span><span>${esc(d.host)}</span></div>
         <div class="kv"><span>错误</span><span style="color:var(--danger)">${esc(d.last_error || "无响应")}</span></div>`}
    </div>`;
  }).join("");
}
function delDevice(name) {
  modal({title: "移除设备", level: "warn",
    body: `确定从网页注册表移除 <code>${esc(name)}</code> 吗？<br>只影响本网页配置，不影响设备本身。`,
    confirmText: "移除",
    onConfirm: async () => {
      try {
        await api(`/api/dev/${name}/delete`, {method: "POST", body: "{}"});
        toast("ok", "已移除", name);
        if (S.view.name === name) go({kind: "overview"});
        loadState();
      } catch (e) { toast("danger", "移除失败", e.message); }
    }});
}

/* ================= device view ================= */
function renderDevice() {
  const d = S.devices.find(x => x.name === S.view.name);
  if (!d) return go({kind: "overview"});
  const tabs = [["status", "📈 概览"], ["logs", "📜 事件日志"],
                ["config", "⚙️ 配置"], ["ops", "🛠 操作"]];
  $("#main").innerHTML = `<div class="view">
    <h1>${esc(d.name)}
      <span class="chip ${d.online?"":"hot"}" style="vertical-align:4px;margin-left:8px">
      ${d.online ? "● 在线" : "○ 离线"}</span></h1>
    <div class="sub">${esc(d.host)}:${d.port} · ${d.proto.toUpperCase()}
      ${d.last_error ? " · <span style='color:var(--danger)'>" + esc(d.last_error) + "</span>" : ""}</div>
    <div class="tabs">${tabs.map(([k, label]) =>
      `<div class="tab ${S.view.tab===k?"active":""}"
            onclick="go({kind:'device',name:'${esc(d.name)}',tab:'${k}'})">${label}</div>`).join("")}
    </div>
    <div id="dev-body"></div></div>`;
  ({status: renderDevStatus, logs: renderDevLogs,
    config: renderDevConfig, ops: renderDevOps})[S.view.tab]();
}

/* ---- tab: status ---- */
async function renderDevStatus() {
  const body = $("#dev-body"); if (!body) return;
  let st = null, lg = null, err = null;
  try {
    const r = await api(`/api/dev/${S.view.name}/status`);
    st = r.status; lg = r.logstats;
  } catch (e) { err = e.message; }
  let perf = null;
  try { perf = (await api(`/api/dev/${S.view.name}/perf`)).perf; }
  catch (e) { /* log dir unreadable — skip silently */ }
  if (S.view.tab !== "status" || !$("#dev-body")) return;
  if (err) {
    body.innerHTML = `<div class="warnbar">⚠️ 无法连接设备：${esc(err)}</div>`;
    return;
  }
  const tcb = st.tcb || {};
  const pd = (perf && perf.data) || {};
  const age = perf && st.uptime_s != null && perf.ts != null
    ? Math.max(0, Math.round(st.uptime_s - perf.ts / 1000)) : null;
  const perfSub = `perf 事件${age != null ? ` · ${age}s 前采样` : ""}`;
  const cards = [
    ["⏱ 运行时间", fmtUp(st.uptime_s), `启动计数 ${st.boot ?? "—"}`],
    ["🧠 内部堆空闲", fmtKB(st.heap_free), `历史最低 ${fmtKB(st.heap_min)}`],
    ...(perf ? [["💾 PSRAM 空闲", fmtKB(pd.psram_free), perfSub]] : []),
    ["🔌 活跃会话", st.sessions_active ?? "—", "全局传输会话预算"],
    ["🐺 wolfSSL 内存", fmtKB(st.wolf_cur), `峰值 ${fmtKB(st.wolf_peak)}`],
    ["🌐 s419 TCB", tcb.estab ?? "—",
      `SYN_RECV ${tcb.syn_recv ?? 0} · TIME_WAIT ${tcb.time_wait ?? 0}`],
    ["📨 日志队列", lg ? `丢弃 ${lg.dropped}` : "—",
      lg ? `已入队 ${lg.queued}` : ""],
    ...(perf && pd.rssi ? [["📶 WiFi 信号", `${pd.rssi} dBm`, perfSub]] : []),
    ...(perf && pd.temp_c_x10 != null && pd.temp_c_x10 !== -1270
        ? [["🌡 芯片温度", `${(pd.temp_c_x10 / 10).toFixed(1)} °C`, perfSub]]
        : []),
    ["🏷 固件版本", esc(st.version || "—"), ""],
  ];
  body.innerHTML = `<div class="cards">${cards.map(([t, v, s]) =>
    `<div class="card"><div class="t">${t}</div><div class="v">${v}</div>
     ${s ? `<div class="s">${s}</div>` : ""}</div>`).join("")}</div>
    ${!perf ? `<div class="warnbar" style="margin-top:16px">💡 <div>
      没有读到 <span class="mono">system.perf</span> 事件，PSRAM / WiFi 信号 /
      温度暂无数据。该事件由设备每 <span class="mono">perf.int_s</span>
      秒上报一次，请确认 log_collector.py 正在接收且日志目录配置正确。</div></div>` : ""}
    ${(st.vdevs || []).length ? `<div class="panel" style="margin-top:18px">
      <div class="ph"><b>虚拟设备</b></div>
      <table><thead><tr><th>地址</th><th>persona</th></tr></thead><tbody>
      ${st.vdevs.map(v => `<tr><td class="mono">${esc(v.ip)}</td>
        <td class="mono">${esc(v.persona)}</td></tr>`).join("")}
      </tbody></table></div>` : ""}`;
}

/* ---- tab: logs ---- */
async function renderDevLogs(reset) {
  const body = $("#dev-body"); if (!body) return;
  if (reset !== false) { S.log = {file: "", offset: null, events: [],
                                  tail: true, fKind: "", fSrc: ""}; }
  body.innerHTML = `<div class="panel">
    <div class="ph"><b>事件日志</b>
      <select id="lg-file"></select>
      <input id="lg-fkind" placeholder="过滤事件类型" style="width:150px">
      <input id="lg-fsrc" placeholder="过滤源 IP" style="width:130px">
      <label style="font-size:12.5px;color:var(--dim);display:flex;gap:6px;align-items:center">
        <input type="checkbox" id="lg-tail" checked style="width:auto"> 实时跟踪</label>
      <span style="margin-left:auto;display:flex;gap:8px;align-items:center">
        <button class="btn sm" id="lg-dl-jsonl" title="导出当前文件为原始 JSONL">⬇ JSONL</button>
        <button class="btn sm" id="lg-dl-csv" title="导出当前文件为 CSV（表格软件可直接打开）">⬇ CSV</button>
        <span id="lg-stats"></span>
      </span>
    </div>
    <div style="max-height:56vh;overflow-y:auto">
    <table><thead><tr><th style="width:170px">时间</th><th style="width:190px">事件</th>
      <th style="width:150px">来源</th><th>详情</th></tr></thead>
      <tbody id="lg-rows"></tbody></table>
    <div class="empty" id="lg-empty" style="display:none">暂无事件</div></div>
  </div>`;
  $("#lg-file").onchange = e => { S.log.file = e.target.value;
    S.log.offset = null; S.log.events = []; pullLogs(); };
  $("#lg-fkind").oninput = e => { S.log.fKind = e.target.value; paintLogs(); };
  $("#lg-fsrc").oninput = e => { S.log.fSrc = e.target.value; paintLogs(); };
  $("#lg-tail").onchange = e => { S.log.tail = e.target.checked;
    if (S.log.tail) pullLogs(); };
  const dl = fmt => {
    if (!S.log.file) return toast("warn", "没有可导出的日志文件");
    const tk = S.token ? `&token=${encodeURIComponent(S.token)}` : "";
    location.href = `/api/dev/${S.view.name}/export?file=${
      encodeURIComponent(S.log.file)}&fmt=${fmt}${tk}`;
    toast("info", "导出已开始", `${S.log.file} → ${fmt.toUpperCase()}`,
          {ms: 3000});
  };
  $("#lg-dl-jsonl").onclick = () => dl("jsonl");
  $("#lg-dl-csv").onclick = () => dl("csv");
  await pullLogs(true);
  S.timers.logs = setInterval(() => { if (S.log.tail) pullLogs(); }, 3000);
}
async function pullLogs(first) {
  const q = new URLSearchParams();
  if (S.log.file) q.set("file", S.log.file);
  if (S.log.offset != null) q.set("after", S.log.offset);
  let r;
  try { r = await api(`/api/dev/${S.view.name}/logs?` + q); }
  catch (e) { if (first) toast("warn", "日志读取失败", e.message); return; }
  const sel = $("#lg-file"); if (!sel) return;
  if (sel.options.length !== r.files.length)
    sel.innerHTML = r.files.map(f =>
      `<option ${f === r.file ? "selected" : ""}>${esc(f)}</option>`).join("");
  S.log.file = r.file; S.log.offset = r.offset;
  if (r.events.length) {
    S.log.events.push(...r.events);
    if (S.log.events.length > 3000)
      S.log.events.splice(0, S.log.events.length - 3000);
    paintLogs();
    if (!first) {
      const bad = r.events.filter(e => /dropped|overload/.test(e.evt || ""));
      if (bad.length) toast("warn", S.view.name,
        `出现 ${bad[0].evt} 事件`, {ms: 4000});
    }
  }
}
const KIND_CLS = k => /login|auth/i.test(k) ? "k-login"
  : /dropped|overload|fail/i.test(k) ? "k-danger"
  : /connect/i.test(k) ? "k-conn" : /command|cmd/i.test(k) ? "k-cmd" : "";
function fmtTs(e) {
  const ts = e.ts;
  if (ts == null) return "—";
  if (ts >= 1e11)                                // epoch ms
    return new Date(ts).toLocaleString("zh-CN", {hour12: false});
  // ms since boot (device event schema)
  const s = Math.floor(ts / 1000), p = x => String(x).padStart(2, "0");
  const d = Math.floor(s / 86400);
  const t = `${p(Math.floor(s % 86400 / 3600))}:${p(Math.floor(s % 3600 / 60))}:${p(s % 60)}`;
  return `T+${d ? d + "d " : ""}${t}${e.boot != null ? " b" + e.boot : ""}`;
}
function paintLogs() {
  const rows = $("#lg-rows"); if (!rows) return;
  const ev = S.log.events.filter(e => {
    if (S.log.fKind && !(e.evt || "").includes(S.log.fKind)) return false;
    if (S.log.fSrc && !(e.sip || "").includes(S.log.fSrc)) return false;
    return true;
  }).slice(-600).reverse();
  $("#lg-empty").style.display = ev.length ? "none" : "";
  rows.innerHTML = ev.map(e => {
    const t = fmtTs(e);
    const data = Object.entries(e.data || {})
      .map(([k, v]) => `${k}=${v}`).join("  ");
    return `<tr><td class="mono" style="color:var(--dim)">${esc(t)}</td>
      <td class="evt-kind ${KIND_CLS(e.evt || "")}">${esc(e.evt)}</td>
      <td class="mono">${esc(e.sip || "?")}:${esc(e.sport ?? "")}</td>
      <td class="mono" style="color:var(--dim);word-break:break-all">${esc(data)}</td></tr>`;
  }).join("");
  const kinds = {}, srcs = {};
  for (const e of S.log.events) {
    if (e.evt) kinds[e.evt] = (kinds[e.evt] || 0) + 1;
    if (e.sip) srcs[e.sip] = (srcs[e.sip] || 0) + 1;
  }
  const top = (o, n) => Object.entries(o).sort((a, b) => b[1] - a[1])
    .slice(0, n).map(([k, v]) => `${esc(k)} ×${v}`).join(" · ");
  $("#lg-stats").innerHTML =
    `<span class="chip">${S.log.events.length} 条</span>
     <span class="chip" title="来源 IP 排行">${top(srcs, 3) || "—"}</span>`;
}

/* ---- tab: config ---- */
async function renderDevConfig() {
  const body = $("#dev-body"); if (!body) return;
  body.innerHTML = `<div class="empty">正在读取配置…</div>`;
  let cfg;
  try { cfg = (await api(`/api/dev/${S.view.name}/cfg`)).cfg; }
  catch (e) {
    body.innerHTML = `<div class="warnbar">⚠️ 读取失败：${esc(e.message)}</div>`;
    return;
  }
  S.cfg[S.view.name] = cfg; S.dirty[S.view.name] = {};
  paintConfig();
}
function paintConfig() {
  const name = S.view.name, cfg = S.cfg[name] || {}, dirty = S.dirty[name] || {};
  const body = $("#dev-body"); if (!body) return;
  const keys = Object.keys(cfg).sort();
  const hasWarnDirty = Object.keys(dirty).some(k => keyInfo(k).warn);
  body.innerHTML = `
    <div id="cfg-warn" class="warnbar" style="display:${hasWarnDirty ? "flex" : "none"}">
      ⚠️ <div>待保存的修改包含<b>网络 / 管理平面</b>参数，保存错误配置可能导致
      <b>设备失联</b>。部分参数标注 <span class="tag rb">reboot</span>，需重启后才生效。</div>
    </div>
    <div class="panel"><table>
      <thead><tr><th style="width:250px">键</th><th>值</th>
        <th style="width:36px"></th><th style="width:150px;text-align:right">操作</th></tr></thead>
      <tbody>${keys.map(k => {
        const info = keyInfo(k), cur = cfg[k], isDirty = k in dirty;
        const val = isDirty ? dirty[k] : cur;
        const t = keyType(k, cur);
        let input;
        if (info.sec && !isDirty)
          input = `<span class="mono" style="color:var(--dim)">***（保密）</span>`;
        else if (t === "bool")
          input = `<div class="switch ${val === "true" ? "on" : ""}"
            onclick="cfgToggle('${esc(k)}')"></div>`;
        else
          input = `<input class="mono" style="width:100%" value="${esc(val)}"
            ${info.sec ? 'type="password" placeholder="输入新值"' : ""}
            oninput="cfgEdit('${esc(k)}', this.value)">`;
        return `<tr id="cfgrow-${esc(k)}">
          <td class="mono" style="white-space:nowrap">${esc(k)}
            ${info.rb ? '<span class="tag rb">reboot</span>' : ""}
            ${info.warn ? '<span class="tag wr">敏感</span>' : ""}</td>
          <td>${input}</td>
          <td><i class="info-ic" onmouseenter="showTip(event,'${esc(k)}')"
                 onmouseleave="hideTip()">i</i></td>
          <td class="rowbtns">${isDirty ? `
            <button class="btn sm primary" onclick="cfgSave('${esc(k)}')">保存</button>
            <button class="btn sm" onclick="cfgUndo('${esc(k)}')">撤销</button>` : ""}
          </td></tr>`;
      }).join("")}</tbody></table></div>`;
}
function cfgEdit(k, v) { S.dirty[S.view.name][k] = v; refreshCfgRow(k); }
function cfgToggle(k) {
  const cur = S.dirty[S.view.name][k] ?? S.cfg[S.view.name][k];
  S.dirty[S.view.name][k] = cur === "true" ? "false" : "true";
  paintConfig();
}
function cfgUndo(k) { delete S.dirty[S.view.name][k]; paintConfig(); }
function refreshCfgRow(k) {
  const hasWarnDirty = Object.keys(S.dirty[S.view.name] || {})
    .some(x => keyInfo(x).warn);
  const wb = $("#cfg-warn"); if (wb) wb.style.display = hasWarnDirty ? "flex" : "none";
  const row = $(`#cfgrow-${CSS.escape(k)}`);
  if (row) row.querySelector(".rowbtns").innerHTML = `
    <button class="btn sm primary" onclick="cfgSave('${esc(k)}')">保存</button>
    <button class="btn sm" onclick="cfgUndo('${esc(k)}')">撤销</button>`;
}
function cfgValidate(k, v) {
  const t = keyType(k, S.cfg[S.view.name][k]);
  if (t === "u32" && !/^\d{1,10}$/.test(v)) return "应为 0–4294967295 的整数";
  if (t === "ip" && v && !/^(\d{1,3}\.){3}\d{1,3}$/.test(v))
    return "应为点分四段 IP（如 192.168.1.10）";
  if (t === "mac" && v && !/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(v))
    return "应为 aa:bb:cc:dd:ee:ff 格式";
  return null;
}
function cfgSave(k) {
  const name = S.view.name, v = S.dirty[name][k], info = keyInfo(k);
  const bad = cfgValidate(k, v);
  if (bad) return toast("warn", "格式校验未通过", `${k}: ${bad}`);
  const doSave = async () => {
    try {
      const r = await api(`/api/dev/${name}/cmd`, {method: "POST",
        body: JSON.stringify({cmd: "set", key: k, value: v})});
      S.cfg[name][k] = keyInfo(k).sec ? "***" : v;
      delete S.dirty[name][k];
      paintConfig();
      const after = typeof r.result === "string" && r.result.includes("reboot");
      toast(after ? "warn" : "ok", "已保存",
        after ? `${k} — 重启后生效` : `${k} = ${info.sec ? "***" : v}`);
      const row = $(`#cfgrow-${CSS.escape(k)} td`);
      if (row) row.classList.add("flash");
    } catch (e) { toast("danger", "保存失败", `${k}: ${e.message}`); }
  };
  if (info.warn)
    modal({title: "敏感配置确认", level: "warn",
      body: `即将修改 <code>${esc(k)}</code>。<br>${esc(info.d)}<br><br>
             <b>错误配置可能导致设备失联</b>，确认继续？`,
      confirmText: "仍然保存", onConfirm: doSave});
  else if (info.sec)
    modal({title: "覆盖保密值", level: "warn",
      body: `将覆盖 <code>${esc(k)}</code> 的保密值，确认？`,
      confirmText: "覆盖", onConfirm: doSave});
  else doSave();
}
let tipEl = null;
function showTip(ev, k) {
  hideTip();
  const info = keyInfo(k);
  tipEl = document.createElement("div");
  tipEl.className = "tooltip";
  tipEl.innerHTML = `<div class="tk">${esc(k)}</div>${esc(info.d)}
    ${info.rb ? '<div style="margin-top:6px;color:var(--warn)">⏻ 修改后需重启生效</div>' : ""}`;
  document.body.appendChild(tipEl);
  const r = ev.target.getBoundingClientRect();
  tipEl.style.left = Math.min(r.left, innerWidth - 320) + "px";
  tipEl.style.top = (r.bottom + 8) + "px";
}
function hideTip() { if (tipEl) { tipEl.remove(); tipEl = null; } }

/* ---- tab: ops ---- */
function renderDevOps() {
  const name = S.view.name;
  $("#dev-body").innerHTML = `<div class="cards" style="grid-template-columns:repeat(auto-fill,minmax(280px,1fr))">
    <div class="card"><div class="t">🧪 发送测试事件</div>
      <div class="sub" style="margin:6px 0 14px">让设备立即产生一条
        <span class="mono">log.test</span> 事件，用于验证采集链路。</div>
      <button class="btn primary" id="op-test">发送</button></div>
    <div class="card"><div class="t">♻️ 恢复默认配置</div>
      <div class="sub" style="margin:6px 0 14px">清除该设备 NVS 中的全部配置覆盖，
        恢复为固件编译默认值。<b style="color:var(--warn)">不可撤销。</b></div>
      <button class="btn warn" id="op-reset">恢复默认</button></div>
    <div class="card"><div class="t">⏻ 重启设备</div>
      <div class="sub" style="margin:6px 0 14px">立即重启。期间管理通道与蜜罐服务
        全部中断，约数秒后恢复。</div>
      <button class="btn danger" id="op-reboot">重启</button></div>
  </div>`;
  $("#op-test").onclick = async () => {
    try {
      await api(`/api/dev/${name}/cmd`, {method: "POST",
        body: JSON.stringify({cmd: "log.test"})});
      toast("ok", "测试事件已发送", "请到事件日志页确认收到");
    } catch (e) { toast("danger", "发送失败", e.message); }
  };
  $("#op-reset").onclick = () => modal({
    title: "恢复默认配置", level: "warn",
    body: `将清除 <code>${esc(name)}</code> 上全部配置覆盖（含网络、日志、
      管理平面参数），恢复编译默认值。<br><br><b>若默认值与当前网络不符，
      设备可能失联。</b>`, confirmText: "恢复默认",
    onConfirm: async () => {
      try {
        await api(`/api/dev/${name}/cmd`, {method: "POST",
          body: JSON.stringify({cmd: "reset"})});
        toast("warn", "已恢复默认配置", "建议随后重启设备");
      } catch (e) { toast("danger", "操作失败", e.message); }
    }});
  $("#op-reboot").onclick = () => modal({
    title: "重启设备", level: "danger", requireText: name,
    body: `即将重启 <code>${esc(name)}</code>。所有蜜罐会话会中断，
      未落盘的运行状态丢失。`, confirmText: "立即重启",
    onConfirm: async () => {
      try {
        await api(`/api/dev/${name}/cmd`, {method: "POST",
          body: JSON.stringify({cmd: "reboot"})});
        toast("danger", "重启指令已下达", `${name} 正在重启…`);
      } catch (e) { toast("danger", "重启失败", e.message); }
    }});
}

/* ================= fmt ================= */
function fmtUp(s) {
  if (s == null) return "—";
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600),
        m = Math.floor(s % 3600 / 60), ss = Math.floor(s % 60);
  const p = x => String(x).padStart(2, "0");
  return (d ? d + "d " : "") + `${p(h)}:${p(m)}:${p(ss)}`;
}
function fmtKB(b) {
  if (b == null) return "—";
  return b > 1048576 ? (b / 1048576).toFixed(1) + " MB"
                     : Math.round(b / 1024) + " KB";
}

/* ================= boot ================= */
loadState();
setInterval(loadState, 5000);
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main():
    global STORE, TOKEN
    ap = argparse.ArgumentParser(description="micropot-c5 management web UI")
    ap.add_argument("--config", default=os.path.join(SCRIPT_DIR,
                                                     "devices.json"),
                    help="device registry file (default: tools/devices.json)")
    ap.add_argument("--bind", default="127.0.0.1",
                    help="bind address (default: 127.0.0.1, local only)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--token", default=os.environ.get("MICROPOT_WEB_TOKEN"),
                    help="access token required for /api/* "
                         "(or env MICROPOT_WEB_TOKEN)")
    args = ap.parse_args()

    # The dashboard can change runtime config and reboot devices. Never let
    # a non-loopback bind expose that unauthenticated.
    loopback = {"127.0.0.1", "::1", "localhost"}
    if args.bind not in loopback and not args.token:
        ap.error("--token (or MICROPOT_WEB_TOKEN) is required when "
                 "--bind is not a loopback address")

    TOKEN = args.token
    STORE = DeviceStore(args.config)
    if not STORE.devices:
        print(f"note: {args.config} 为空或不存在 — 可在网页中添加设备")

    stop = threading.Event()
    t = threading.Thread(target=poller, args=(STORE, stop), daemon=True)
    t.start()

    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    warn = "" if args.bind in ("127.0.0.1", "::1") else \
        "  ⚠ 绑定到非本机地址，请务必使用 --token 保护！\n"
    print(f"micropot-web  http://{args.bind}:{args.port}  "
          f"({len(STORE.devices)} device(s))\n{warn}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.shutdown()


if __name__ == "__main__":
    main()
