#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hogwarts_server.py — Hogwarts Gateway (Server, WAF entegre)
- HTTP + PHP-CGI
- WAF (hogwarts_waf.py) entegrasyonu: header taraması, shadow mode, policy’ler
- Rate-limit (token bucket) + geçici ban
- Güvenlik başlıkları, MIME tipi, statik dosya, dizin listeleme opsiyonu
- HTML hata sayfaları
- config.json + CLI override
"""

import os, sys, io, re, json, time, ipaddress, argparse, mimetypes, urllib.parse, subprocess, threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import hogwarts_waf as WAF  # ← WAF modülün

# ── Branding
PRODUCT_NAME   = "Hogwarts Gateway"
SERVER_VERSION = "Hogwarts Gateway/ULTRA"

# ── Defaults / Limits
DEFAULT_INDEXES = ["index.php", "index.html"]
DEFAULT_PHP_CGI = "php-cgi"
DEFAULT_DOCROOT = os.path.abspath(os.path.join(os.getcwd(), "www"))

MAX_BODY = 10 * 1024 * 1024
MAX_URI = 2048
MAX_HEADER_COUNT = 100
MAX_HEADER_LINE = 8 * 1024
READ_TIMEOUT = 20

PHP_TIMEOUT_DEFAULT = 30
AUTO_INDEX_DEFAULT  = False

SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'self'",
}

# ── App-layer firewall (rate/ban)
RATE_PER_SEC = 10.0
RATE_BURST   = 20.0
BAN_THRESHOLD= 20
BAN_WINDOW   = 60
BAN_DURATION = 300

# ── Helpers
def safe_join(base, *paths):
    p = os.path.normpath(os.path.join(base, *paths))
    if os.path.commonpath([os.path.abspath(p), os.path.abspath(base)]) != os.path.abspath(base):
        raise PermissionError("Path traversal")
    return p

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

_ip_tokens, _ip_errs, _ip_bans = {}, {}, {}
_lock = threading.Lock()
def now(): return time.time()

def firewall_is_banned(ip):
    with _lock:
        until = _ip_bans.get(ip)
        if until and until > now(): return True, int(until - now())
        if until: _ip_bans.pop(ip, None)
    return False, 0

def firewall_add_error(ip, cfg):
    t = now()
    with _lock:
        lst = _ip_errs.setdefault(ip, [])
        lst.append(t)
        cutoff = t - cfg["ban_window"]
        while lst and lst[0] < cutoff: lst.pop(0)
        if len(lst) >= cfg["ban_threshold"]:
            _ip_bans[ip] = t + cfg["ban_duration"]; _ip_errs[ip] = []

def ratelimit_allow(ip, cfg):
    t = now()
    with _lock:
        tokens, last = _ip_tokens.get(ip, (cfg["rate_burst"], t))
        tokens = min(cfg["rate_burst"], tokens + (t - last) * cfg["rate_per_sec"])
        if tokens >= 1: _ip_tokens[ip] = (tokens-1, t); return True
        _ip_tokens[ip] = (tokens, t); return False

def ip_in_cidrs(ip, cidrs):
    if not cidrs: return False
    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in net for net in cidrs)

def parse_cidrs(cidrs):
    nets = []
    for c in cidrs or []:
        try: nets.append(ipaddress.ip_network(c, strict=False))
        except: print(f"[!] Invalid CIDR: {c}", file=sys.stderr)
    return nets

def html_error_page(code: int, title: str, detail: str) -> bytes:
    return f"""<!doctype html>
<meta charset="utf-8"><title>{code} {title}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:720px;margin:6rem auto;color:#222}}
h1{{font-size:1.6rem}}.box{{padding:12px 14px;border:1px solid #ddd;border-radius:8px;background:#fafafa}}
footer{{margin-top:2rem;color:#666}}code{{font-family:ui-monospace,monospace}}
</style>
<body>
  <h1>{code} — {title}</h1>
  <div class="box">{detail}</div>
  <footer>Powered by <strong>{PRODUCT_NAME}</strong></footer>
</body>""".encode()

# ── Handler
class HogwartsHandler(BaseHTTPRequestHandler):
    server_version = SERVER_VERSION
    docroot = DEFAULT_DOCROOT
    php_cgi = DEFAULT_PHP_CGI
    index_files = DEFAULT_INDEXES
    auto_index = AUTO_INDEX_DEFAULT

    cfg = {
        "allow_cidrs": [],
        "deny_cidrs": [],
        "rate_per_sec": RATE_PER_SEC,
        "rate_burst": RATE_BURST,
        "ban_threshold": BAN_THRESHOLD,
        "ban_window": BAN_WINDOW,
        "ban_duration": BAN_DURATION,
        "security_headers": SEC_HEADERS,
        "php_timeout": PHP_TIMEOUT_DEFAULT,
    }

    def client_ip(self): return self.client_address[0] if self.client_address else ""

    def apply_sec_headers(self):
        for k, v in self.cfg["security_headers"].items(): self.send_header(k, v)

    def send_html_error(self, code, title, detail):
        body = html_error_page(code, title, detail)
        self.send_response(code, title)
        self.apply_sec_headers()
        self.send_header("Server", SERVER_VERSION)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try: self.wfile.write(body)
        except: pass

    def validate_request_size(self):
        if len(self.path) > MAX_URI: self.send_html_error(414, "URI Too Long", "URI çok uzun."); return False
        if len(self.headers) > MAX_HEADER_COUNT: self.send_html_error(431, "Header Fields Too Large", "Başlık sayısı çok fazla."); return False
        for k, v in self.headers.items():
            if len(k) + len(v) > MAX_HEADER_LINE:
                self.send_html_error(431, "Header Field Too Large", f"Başlık çok uzun: {k}")
                return False
        return True

    def read_body(self):
        cl = int(self.headers.get('Content-Length', 0) or 0)
        if cl > MAX_BODY: self.send_html_error(413, "Payload Too Large", "Gövde çok büyük."); return None
        if cl == 0: return b""
        try: return self.rfile.read(cl)
        except: self.send_html_error(408, "Request Timeout", "Okuma zaman aşımı."); return None

    def translate_path(self, path):
        path = path.split('?',1)[0].split('#',1)[0]
        trailing_slash = path.endswith('/')
        parts = [p for p in path.split('/') if p and p not in ('.','..')]
        try: full = safe_join(self.docroot, *parts)
        except PermissionError: return None
        if os.path.isdir(full):
            if trailing_slash:
                for idx in self.index_files:
                    cand = os.path.join(full, idx)
                    if os.path.isfile(cand): return cand
            return full + ("/" if trailing_slash else "")
        return full

    def guess_type(self, path):
        if not mimetypes.inited: mimetypes.init()
        return mimetypes.types_map.get(os.path.splitext(path)[1].lower(), "application/octet-stream")

    # Methods
    def do_HEAD(self): self.handle_method(head_only=True)
    def do_GET(self):  self.handle_method(head_only=False)
    def do_POST(self): self.handle_method(head_only=False)
    def do_PUT(self): self.send_html_error(405, "Method Not Allowed", "PUT kapalı.")
    def do_DELETE(self): self.send_html_error(405, "Method Not Allowed", "DELETE kapalı.")
    def do_OPTIONS(self): self.send_html_error(405, "Method Not Allowed", "OPTIONS kapalı.")
    def do_PATCH(self): self.send_html_error(405, "Method Not Allowed", "PATCH kapalı.")
    def do_TRACE(self): self.send_html_error(405, "Method Not Allowed", "TRACE kapalı.")
    def do_CONNECT(self): self.send_html_error(405, "Method Not Allowed", "CONNECT kapalı.")

    def handle_method(self, head_only=False):
        ip = self.client_ip()
        cfg = self.cfg

        # Ban / ACL / Rate / Limits
        banned, sec = firewall_is_banned(ip)
        if banned: self.send_html_error(403, "Forbidden", f"Geçici banlı ({sec} sn)."); return
        if cfg["deny_cidrs"] and ip_in_cidrs(ip, cfg["deny_cidrs"]): self.send_html_error(403, "Forbidden", "Deny listesinde."); return
        if cfg["allow_cidrs"] and not ip_in_cidrs(ip, cfg["allow_cidrs"]): self.send_html_error(403, "Forbidden", "Allow listede değil."); return
        if not ratelimit_allow(ip, cfg): self.send_html_error(429, "Too Many Requests", "Hız limiti aşıldı."); return
        if not self.validate_request_size(): firewall_add_error(ip, cfg); return

        parsed = urllib.parse.urlsplit(self.path)

        body = b""
        if self.command == "POST":
            body = self.read_body()
            if body is None: firewall_add_error(ip, cfg); return

        # ── WAF (ULTRA) — headers + body
        headers_dict = {k: v for k, v in self.headers.items()}
        waf_pass, rule = WAF.waf_ok_full(self.path, self.command, headers_dict, body if self.command=="POST" else b"")
        if not waf_pass:
            # BLOCK
            self.send_response(406, "Not Acceptable (blocked by WAF)")
            self.apply_sec_headers()
            self.send_header("Server", SERVER_VERSION)
            if WAF.DEBUG_WAF and rule: self.send_header("X-HGWAF-Rule", str(rule)[:200])
            page = html_error_page(406, "Not Acceptable", "İstek WAF tarafından engellendi.")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            try: self.wfile.write(page)
            except: pass
            firewall_add_error(ip, cfg)
            return
        else:
            # SHADOW ⇒ izin ver ama işaretle (ve isteğe bağlı graylist)
            if rule and str(rule).startswith("SHADOW:"):
                # NOT: log için header atıyoruz; istersen graylist de aç:
                # firewall_add_error(ip, cfg)  # shadow hit'leri de say
                self.send_header("X-HGWAF-Shadow", str(rule)[:200])

        # ── Path map
        fs_path = self.translate_path(parsed.path)
        if fs_path is None:
            self.send_html_error(403, "Forbidden", "Yol reddedildi."); firewall_add_error(ip, cfg); return

        # Dir?
        if os.path.isdir(fs_path):
            if not parsed.path.endswith('/'):
                new = parsed.path + '/' + (f"?{parsed.query}" if parsed.query else "")
                self.send_response(301); self.apply_sec_headers(); self.send_header("Server", SERVER_VERSION)
                self.send_header("Location", new); self.end_headers(); return
            if not self.auto_index:
                self.send_html_error(403, "Forbidden", "Dizin listeleme kapalı."); firewall_add_error(ip, cfg); return
            try:
                entries = os.listdir(fs_path.rstrip('/'))
                body_html = "<ul>" + "".join(
                    f'<li><a href="{urllib.parse.quote(name)}">{name}</a></li>' for name in entries
                ) + "</ul>"
                page = f"<!doctype html><meta charset='utf-8'><title>Index of {parsed.path}</title>{body_html}".encode()
                self.send_response(200); self.apply_sec_headers(); self.send_header("Server", SERVER_VERSION)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page))); self.end_headers(); self.wfile.write(page)
            except Exception as e:
                self.send_html_error(500, "Internal Server Error", f"Autoindex hata: {e}")
            return

        # PHP?
        if fs_path.lower().endswith(".php"):
            self.handle_php(fs_path, body, head_only=head_only); return

        # Static
        if not os.path.isfile(fs_path): self.send_html_error(404, "Not Found", "Dosya bulunamadı."); firewall_add_error(ip, cfg); return
        try:
            size = os.path.getsize(fs_path)
            self.send_response(200)
            self.apply_sec_headers()
            self.send_header("Content-Type", self.guess_type(fs_path))
            self.send_header("Content-Length", str(size))
            self.send_header("Last-Modified", self.date_time_string(os.path.getmtime(fs_path)))
            self.send_header("Server", SERVER_VERSION)
            self.end_headers()
            if not head_only:
                with open(fs_path, "rb") as f:
                    for chunk in iter(lambda: f.read(64*1024), b""): self.wfile.write(chunk)
        except Exception as e:
            self.send_html_error(404, "Not Found", f"Okuma hatası: {e}"); firewall_add_error(ip, cfg)

    def handle_php(self, script_filename, body, head_only=False):
        parsed = urllib.parse.urlsplit(self.path)
        query = parsed.query or ""
        env = os.environ.copy()
        env.update({
            "GATEWAY_INTERFACE":"CGI/1.1",
            "REQUEST_METHOD":self.command,
            "SCRIPT_FILENAME":os.path.abspath(script_filename),
            "SCRIPT_NAME":parsed.path,
            "PATH_INFO":parsed.path,
            "QUERY_STRING":query,
            "REQUEST_URI":self.path,
            "DOCUMENT_ROOT":self.docroot,
            "REMOTE_ADDR":self.client_address[0] if self.client_address else "",
            "REMOTE_PORT":str(self.client_address[1]) if self.client_address else "",
            "SERVER_ADDR":self.server.server_address[0] if hasattr(self.server,"server_address") else "",
            "SERVER_PORT":str(self.server.server_address[1]) if hasattr(self.server,"server_address") else "",
            "SERVER_NAME":self.server.server_name if hasattr(self.server,"server_name") else "localhost",
            "SERVER_PROTOCOL":self.protocol_version,
            "SERVER_SOFTWARE":SERVER_VERSION,
            "REDIRECT_STATUS":"200",
        })
        ct = self.headers.get('Content-Type')
        if ct: env["CONTENT_TYPE"] = ct
        if body: env["CONTENT_LENGTH"] = str(len(body))
        for k, v in self.headers.items():
            hk = "HTTP_" + k.upper().replace("-","_")
            if hk in ("HTTP_CONTENT_TYPE","HTTP_CONTENT_LENGTH"): continue
            env[hk] = v

        try:
            p = subprocess.Popen([self.php_cgi, "-q"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            stdout, stderr = p.communicate(input=(body if self.command=="POST" else None), timeout=self.cfg.get("php_timeout", PHP_TIMEOUT_DEFAULT))
        except FileNotFoundError:
            self.send_html_error(500, "php-cgi not found", "PHP CGI bulunamadı."); firewall_add_error(self.client_ip(), self.cfg); return
        except subprocess.TimeoutExpired:
            p.kill(); sys.stderr.write(f"[{PRODUCT_NAME}] php-cgi timeout: {script_filename}\n")
            self.send_html_error(504, "PHP Gateway Timeout", "PHP geç cevap verdi."); firewall_add_error(self.client_ip(), self.cfg); return

        # Parse CGI headers
        header_end = stdout.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = stdout.find(b"\n\n")
            if header_end == -1:
                self.send_html_error(500, "Invalid CGI output", "CGI başlıkları eksik."); firewall_add_error(self.client_ip(), self.cfg); return

        raw = stdout[:header_end].decode("iso-8859-1","replace")
        body_part = stdout[header_end+4:] if stdout[header_end:header_end+4]==b"\r\n\r\n" else stdout[header_end+2:]

        status_code, status_text, headers = 200, "OK", []
        for line in raw.splitlines():
            if not line.strip(): continue
            if ":" not in line:
                if line.lower().startswith("status"):
                    _, val = (line.split(None,1)+[""])[:2]
                    parts = val.split(None,1)
                    try: status_code = int(parts[0]); status_text = parts[1] if len(parts)>1 else ""
                    except: pass
                continue
            k, v = line.split(":",1)
            headers.append((k.strip(), v.strip()))

        self.send_response(status_code, status_text)
        sent_ct = False
        for k, v in headers:
            if k.lower()=="status": continue
            if k.lower()=="content-type": sent_ct = True
            self.send_header(k, v)
        if not sent_ct: self.send_header("Content-Type","text/html; charset=utf-8")
        self.apply_sec_headers()
        self.send_header("Server", SERVER_VERSION)
        self.end_headers()
        if not head_only:
            try: self.wfile.write(body_part)
            except: pass

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), datetime.now().strftime("%d/%b/%Y:%H:%M:%S"), fmt % args))

# ── Config
def load_config(path):
    with open(path,"r",encoding="utf-8") as f: raw=json.load(f)
    return {
        "host": raw.get("host","127.0.0.1"),
        "port": int(raw.get("port",8080)),
        "docroot": raw.get("docroot", DEFAULT_DOCROOT),
        "php_cgi": raw.get("php_cgi", DEFAULT_PHP_CGI),
        "allow": raw.get("allow",[]),
        "deny": raw.get("deny",[]),
        "rate": float(raw.get("rate",RATE_PER_SEC)),
        "burst": float(raw.get("burst",RATE_BURST)),
        "ban_threshold": int(raw.get("ban_threshold",BAN_THRESHOLD)),
        "ban_window": int(raw.get("ban_window",BAN_WINDOW)),
        "ban_duration": int(raw.get("ban_duration",BAN_DURATION)),
        "auto_index": bool(raw.get("auto_index", AUTO_INDEX_DEFAULT)),
        "php_timeout": int(raw.get("php_timeout", PHP_TIMEOUT_DEFAULT)),

        # WAF ayarları (doğrudan WAF.load_config'a gidecek)
        "waf_enabled": raw.get("waf_enabled", WAF.WAF_ENABLED),
        "waf_only_on_input": raw.get("waf_only_on_input", WAF.WAF_ONLY_ON_INPUT),
        "waf_debug": raw.get("waf_debug", WAF.DEBUG_WAF),
        "waf_scan_headers": raw.get("waf_scan_headers", WAF.SCAN_HEADERS),
        "waf_paranoia": raw.get("waf_paranoia", WAF.PARANOIA_LEVEL),
        "waf_score_threshold": raw.get("waf_score_threshold", WAF.SCORE_THRESHOLD),
        "waf_shadow_mode": raw.get("waf_shadow_mode", WAF.WAF_SHADOW_MODE),
        "waf_whitelist_paths": raw.get("waf_whitelist_paths", WAF.WHITELIST_PATHS),
        "waf_honeypots": raw.get("waf_honeypots", WAF.HONEY_POTS),
        "waf_path_policies": raw.get("waf_path_policies", WAF.PATH_POLICIES),
        "waf_param_policies": raw.get("waf_param_policies", WAF.PARAM_POLICIES),
        "waf_param_violation_score": raw.get("waf_param_violation_score", WAF.PARAM_VIOLATION_SCORE),
        "waf_normalize_loops": raw.get("waf_normalize_loops", WAF.MAX_NORMALIZE_LOOPS),
        "waf_try_base64": raw.get("waf_try_base64", WAF.TRY_BASE64_DECODE),
        "waf_b64_max_len": raw.get("waf_b64_max_len", WAF.B64_MAX_LEN),
        "waf_upload_max_mb": raw.get("waf_upload_max_mb", WAF.MAX_UPLOAD_MB),
        "waf_forbidden_ext": raw.get("waf_forbidden_ext", list(WAF.FORBIDDEN_EXT)),
    }

def merge_cli_over_config(args, cfg):
    def first(a,b): return a if a is not None else b
    out = dict(cfg)
    # Server
    out["host"] = first(args.host, cfg["host"])
    out["port"] = int(first(args.port, cfg["port"]))
    out["docroot"] = first(args.docroot, cfg["docroot"])
    out["php_cgi"] = first(args.php_cgi, cfg["php_cgi"])
    out["allow"] = first(args.allow, cfg["allow"])
    out["deny"]  = first(args.deny, cfg["deny"])
    out["rate"]  = float(first(args.rate, cfg["rate"]))
    out["burst"] = float(first(args.burst, cfg["burst"]))
    out["ban_threshold"] = int(first(args.ban_threshold, cfg["ban_threshold"]))
    out["ban_window"]    = int(first(args.ban_window, cfg["ban_window"]))
    out["ban_duration"]  = int(first(args.ban_duration, cfg["ban_duration"]))
    out["auto_index"]    = bool(first(args.auto_index, cfg["auto_index"]))
    out["php_timeout"]   = int(first(args.php_timeout, cfg["php_timeout"]))
    # WAF
    out["waf_enabled"] = first(args.waf_enabled, cfg["waf_enabled"])
    out["waf_only_on_input"] = first(args.waf_only_on_input, cfg["waf_only_on_input"])
    out["waf_debug"] = first(args.waf_debug, cfg["waf_debug"])
    out["waf_scan_headers"] = first(args.waf_scan_headers, cfg["waf_scan_headers"])
    out["waf_paranoia"] = int(first(args.waf_paranoia, cfg["waf_paranoia"]))
    out["waf_score_threshold"] = int(first(args.waf_score_threshold, cfg["waf_score_threshold"]))
    out["waf_shadow_mode"] = first(args.waf_shadow_mode, cfg["waf_shadow_mode"])
    out["waf_whitelist_paths"] = first(args.waf_whitelist_paths, cfg["waf_whitelist_paths"])
    # diğerleri config.json’dan gelsin yeter
    return out

def main():
    ap = argparse.ArgumentParser(description=f"{PRODUCT_NAME} — {SERVER_VERSION}")
    ap.add_argument("--config")
    ap.add_argument("--host"); ap.add_argument("--port", type=int)
    ap.add_argument("--docroot"); ap.add_argument("--php-cgi")
    ap.add_argument("--allow", nargs="*"); ap.add_argument("--deny", nargs="*")
    ap.add_argument("--rate", type=float); ap.add_argument("--burst", type=float)
    ap.add_argument("--ban-threshold", type=int); ap.add_argument("--ban-window", type=int); ap.add_argument("--ban-duration", type=int)
    ap.add_argument("--auto-index", type=lambda x: x.lower() in ("1","true","yes"))
    ap.add_argument("--php-timeout", type=int)
    # WAF CLI (en kritikler)
    ap.add_argument("--waf-enabled", type=lambda x: x.lower() in ("1","true","yes"))
    ap.add_argument("--waf-only-on-input", type=lambda x: x.lower() in ("1","true","yes"))
    ap.add_argument("--waf-debug", type=lambda x: x.lower() in ("1","true","yes"))
    ap.add_argument("--waf-scan-headers", type=lambda x: x.lower() in ("1","true","yes"))
    ap.add_argument("--waf-paranoia", type=int)
    ap.add_argument("--waf-score-threshold", type=int)
    ap.add_argument("--waf-shadow-mode", type=lambda x: x.lower() in ("1","true","yes"))
    ap.add_argument("--waf-whitelist-paths", nargs="*")
    args = ap.parse_args()

    base_cfg = {
        "host":"127.0.0.1","port":8080,"docroot":DEFAULT_DOCROOT,"php_cgi":DEFAULT_PHP_CGI,
        "allow":[], "deny":[], "rate":RATE_PER_SEC, "burst":RATE_BURST,
        "ban_threshold":BAN_THRESHOLD, "ban_window":BAN_WINDOW, "ban_duration":BAN_DURATION,
        "auto_index": AUTO_INDEX_DEFAULT, "php_timeout": PHP_TIMEOUT_DEFAULT,
        "waf_enabled": WAF.WAF_ENABLED, "waf_only_on_input": WAF.WAF_ONLY_ON_INPUT,
        "waf_debug": WAF.DEBUG_WAF, "waf_scan_headers": WAF.SCAN_HEADERS,
        "waf_paranoia": WAF.PARANOIA_LEVEL, "waf_score_threshold": WAF.SCORE_THRESHOLD,
        "waf_shadow_mode": WAF.WAF_SHADOW_MODE, "waf_whitelist_paths": WAF.WHITELIST_PATHS,
    }
    if args.config:
        base_cfg = load_config(args.config)
    cfg = merge_cli_over_config(args, base_cfg)

    # Handler bind
    handler = HogwartsHandler
    handler.docroot = os.path.abspath(cfg["docroot"])
    handler.php_cgi = cfg["php_cgi"]
    handler.index_files = DEFAULT_INDEXES
    handler.auto_index = cfg["auto_index"]
    handler.cfg = {
        "allow_cidrs": parse_cidrs(cfg["allow"]),
        "deny_cidrs": parse_cidrs(cfg["deny"]),
        "rate_per_sec": cfg["rate"],
        "rate_burst": cfg["burst"],
        "ban_threshold": cfg["ban_threshold"],
        "ban_window": cfg["ban_window"],
        "ban_duration": cfg["ban_duration"],
        "security_headers": SEC_HEADERS,
        "php_timeout": cfg["php_timeout"],
    }

    if not os.path.isdir(handler.docroot):
        print(f"[!] Docroot missing: {handler.docroot}", file=sys.stderr); sys.exit(1)

    # WAF config uygula
    WAF.load_config(cfg)

    print(f"[*] {PRODUCT_NAME} listening on http://{cfg['host']}:{cfg['port']}  docroot={handler.docroot}")
    print(f"[*] PHP CGI: {handler.php_cgi}")
    print(f"[*] AutoIndex: {'ON' if cfg['auto_index'] else 'OFF'}")
    print(f"[*] WAF: {'ON' if cfg['waf_enabled'] else 'OFF'} | headers={cfg['waf_scan_headers']} | PL={cfg['waf_paranoia']} | thr={cfg['waf_score_threshold']} | shadow={cfg['waf_shadow_mode']}")

    httpd = ThreadingHTTPServer((cfg["host"], cfg["port"]), handler)
    httpd.timeout = READ_TIMEOUT
    try:
        while True: httpd.handle_request()
    except KeyboardInterrupt:
        print("\n[!] Shutting down…")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    main()
