# -*- coding: utf-8 -*-
# hogwarts_waf.py — Hogwarts Gateway WAF (ULTRA / FINAL)
# Normalize: NFKC + multi URL-decode + HTML entity + \xHH + \uXXXX + UTF-7 hint; null byte; whitespace collapse
# Headers scanning (optional), gzip/deflate body decode, base64 expansion (safe limits)
# Multipart upload checks: forbidden ext + basic magic numbers + size
# Per-path policies (pl/threshold/action), honeypots, shadow mode
# Anomaly scoring with extensive signatures: XSS, SQLi, NoSQLi, SSTI, XXE, OS cmd, LFI/RFI/Traversal, SSRF, GQL introspection, LDAPi, path poisoning, null byte
# Backward compatible API: waf_ok(path, method, body) and waf_ok_full(path, method, headers, body)

import re
import os
import html
import zlib
import gzip
import json
import base64
import urllib.parse
import unicodedata
from fnmatch import fnmatch
from typing import Dict, Tuple, Optional, List

# ===================== Global Config (overridable via load_config) =====================
WAF_ENABLED: bool         = True
WAF_ONLY_ON_INPUT: bool   = True      # Sadece query/body varsa tarama
DEBUG_WAF: bool           = True
SCAN_HEADERS: bool        = True
PARANOIA_LEVEL: int       = 3         # 1..3 (3 = en agresif)
SCORE_THRESHOLD: int      = 8         # toplam skor >= threshold ⇒ blok
WAF_SHADOW_MODE: bool     = False     # True => bloklama yerine izin + SHADOW bilgisi
WHITELIST_PATHS: List[str]= []        # örn: ["/healthz"]

# Honeypot & path policies
HONEY_POTS: List[str]     = ["/wp-admin", "/phpmyadmin", "/.env", "/.git", "/boaform", "/HNAP1"]
PATH_POLICIES: Dict[str, dict] = {
    # örnek: "POST:/login": {"pl":3, "threshold":6, "action":"block"}
}

# Param policy (hafif AF)
PARAM_POLICIES: Dict[str, dict] = {}
PARAM_VIOLATION_SCORE: int = 3

# Normalization knobs
MAX_NORMALIZE_LOOPS: int  = 2         # URL decode turları
TRY_BASE64_DECODE: bool   = True
B64_MAX_LEN: int          = 4096

# Upload constraints
FORBIDDEN_EXT = {
    ".php",".php3",".php4",".php5",".phtml",".phar",".cgi",".fcgi",
    ".jsp",".asp",".aspx",".jspx",".js",".mjs",".exe",".dll",".so",".sh",".bat",".cmd",".vbs",".ps1"
}
ALLOW_MAGIC = {
    b"\x89PNG\r\n\x1a\n": "png",
    b"\xff\xd8\xff": "jpg",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"%PDF-": "pdf",
    b"PK\x03\x04": "zip",
}
MAX_UPLOAD_MB = 16

# ===================== Helpers =====================
_rx_hex = re.compile(r'\\x([0-9a-fA-F]{2})')
_rx_uni = re.compile(r'\\u([0-9a-fA-F]{4})')
_rx_b64 = re.compile(r'\b[A-Za-z0-9+/_-]{22,}={0,2}\b')
_rx_utf7_hint = re.compile(r'\+ADw-|Adw-|AEw8')  # "<" benzeri UTF-7 izleri

def _unescape_hex(s: str) -> str:
    return _rx_hex.sub(lambda m: chr(int(m.group(1), 16)), s)

def _unescape_uni(s: str) -> str:
    return _rx_uni.sub(lambda m: chr(int(m.group(1), 16)), s)

def _collapse_ws(s: str) -> str:
    return re.sub(r'\s+', ' ', s).strip()

def _nfkc(s: str) -> str:
    # unicode confusable/homoglyph azaltımı için NFKC
    try:
        return unicodedata.normalize('NFKC', s)
    except Exception:
        return s

def _safe_b64_decode(ch: str) -> Optional[str]:
    if len(ch) > B64_MAX_LEN:
        return None
    cand = ch.replace('-', '+').replace('_', '/')
    pad = len(cand) % 4
    if pad: cand += '=' * (4 - pad)
    try:
        out = base64.b64decode(cand, validate=False)
        return out.decode('utf-8', 'ignore') if out else None
    except Exception:
        return None

def _expand_b64(s: str) -> str:
    if not TRY_BASE64_DECODE:
        return s
    parts, last = [], 0
    for m in _rx_b64.finditer(s):
        parts.append(s[last:m.start()])
        dec = _safe_b64_decode(m.group(0))
        if dec:
            parts.append(f" [B64_DEC:{dec}] ")
        else:
            parts.append(m.group(0))
        last = m.end()
    parts.append(s[last:])
    return ''.join(parts)

def _decode_content(body: bytes, headers: Optional[Dict[str, str]]) -> bytes:
    if not headers or not body: 
        return body or b""
    enc = (headers.get("Content-Encoding","") or "").lower()
    try:
        if enc == "gzip":     return gzip.decompress(body)
        if enc == "deflate":  return zlib.decompress(body)
    except Exception:
        return body
    return body

def _check_multipart(headers: Dict[str,str], body: bytes) -> Optional[str]:
    ct = headers.get("Content-Type","")
    if not ct or not ct.startswith("multipart/form-data"): 
        return None
    m = re.search(r'boundary=([^;]+)', ct)
    if not m: return "multipart: boundary missing"
    boundary = m.group(1).strip().strip('"').encode()
    if len(body) > MAX_UPLOAD_MB*1024*1024:
        return f"multipart: payload > {MAX_UPLOAD_MB}MB"
    for seg in body.split(b"--"+boundary):
        if b"Content-Disposition:" not in seg: 
            continue
        fn = re.search(br'filename="([^"]+)"', seg)
        if fn:
            name = fn.group(1).decode("utf-8","ignore").lower()
            _, ext = os.path.splitext(name)
            if ext in FORBIDDEN_EXT:
                return f"multipart: forbidden ext {ext}"
        p = seg.find(b"\r\n\r\n")
        if p != -1:
            sample = seg[p+4:p+12]
            # Magic sadece bilinen formatlar için ipucu; yokluğu blok sebebi değildir.
            for sig in ALLOW_MAGIC:
                if sample.startswith(sig):
                    break
    return None

def _normalize(method: str, path: str, body: bytes, headers: Optional[Dict[str,str]]) -> str:
    parsed = urllib.parse.urlsplit(path)
    line = f"{method} {parsed.path}"
    if parsed.query: line += f"?{parsed.query}"

    acc = [line]
    if headers and SCAN_HEADERS:
        acc.append("\n".join(f"{k}: {v}" for k, v in headers.items()))
    if body:
        try:
            acc.append(body.decode("utf-8","ignore"))
        except Exception:
            pass

    txt = "\n".join(acc)
    # NFKC
    txt = _nfkc(txt)
    # URL-decode (multi)
    for _ in range(max(1, MAX_NORMALIZE_LOOPS)):
        txt = urllib.parse.unquote(txt)
    # HTML entities
    txt = html.unescape(txt)
    # \xHH, \uXXXX
    txt = _unescape_hex(txt)
    txt = _unescape_uni(txt)
    # UTF-7 hint'i bilinir; sadece skora katkı için işaretleyeceğiz.
    if _rx_utf7_hint.search(txt):
        txt += " [UTF7_HINT]"
    # Null byte temizle
    txt = txt.replace('\x00', '')
    # Base64 genişlet
    txt = _expand_b64(txt)
    # Whitespace
    txt = _collapse_ws(txt)
    return txt

# ===================== Rule Set (name, score, pattern, paranoia_min) =====================
RULES: List[Tuple[str, int, re.Pattern, int]] = []

def _add(name: str, score: int, pattern: bytes, pl: int = 1, flags: int = 0):
    RULES.append((name, score, re.compile(pattern, flags), pl))

# --- XSS ---
_add("xss-script",        5, rb'(?i)(?:<|%3c|&lt;)\s*script\b', 1)
_add("xss-js-protocol",   4, rb'(?i)\bjavascript\s*:', 1)
_add("xss-data-html",     3, rb'(?i)\bdata\s*:\s*text/html', 2)
_add("xss-on-event",      3, rb'(?i)\bon[a-z]+\s*=', 1)
_add("xss-danger-tags",   3, rb'(?i)<\s*(?:img|svg|iframe|object|embed|link|meta|base)\b', 2)
_add("xss-srcdoc",        3, rb'(?i)\bsrcdoc\s*=', 2)
_add("xss-cookie",        4, rb'(?i)document\s*\.\s*cookie', 2)
_add("xss-dom-sinks",     3, rb'(?i)\b(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML)\b', 2)
_add("xss-funcs",         4, rb'(?i)\b(?:eval|Function|setTimeout|setInterval)\s*\(', 2)
_add("xss-utf7",          2, rb'UTF7_HINT', 3)

# --- SQLi ---
_add("sqli-union-all",    5, rb'(?i)\bunion\s+all\s+select\b', 1)
_add("sqli-union",        4, rb'(?i)\bunion\s+select\b', 1)
_add("sqli-order-by",     2, rb'(?i)\border\s+by\s+\d+\b', 2)
_add("sqli-group-concat", 2, rb'(?i)\bgroup_concat\s*\(', 2)
_add("sqli-concat",       2, rb'(?i)\bconcat\s*\(', 2)
_add("sqli-sleep",        5, rb'(?i)\bsleep\s*\(', 1)
_add("sqli-benchmark",    4, rb'(?i)\bbenchmark\s*\(', 2)
_add("sqli-load_file",    4, rb'(?i)\bload_file\s*\(', 2)
_add("sqli-into-outfile", 4, rb'(?i)\binto\s+outfile\b', 2)
_add("sqli-info-schema",  3, rb'(?i)\binformation_schema\b', 1)
_add("sqli-mssql",        4, rb'(?i)\b(?:waitfor\s+delay|xp_cmdshell)\b', 2)
_add("sqli-pg",           3, rb'(?i)\bpg_sleep\s*\(', 2)
_add("sqli-or-bool",      3, rb"(?i)\b(?:or|and)\b\s+\d+\s*=\s*\d+", 3)
_add("sqli-or-1eq1-sq",   4, rb"(?i)'\s*or\s*'1'\s*=\s*'1", 1)
_add("sqli-or-1eq1-dq",   4, rb'(?i)"\s*or\s*"1"\s*=\s*"1', 1)
_add("sqli-comment",      2, rb"(?i)(?:--|#).*$", 2, flags=re.M)
_add("sqli-c-comment",    2, rb"(?s)/\*.*?\*/", 2)

# --- NoSQLi (Mongo-like / JSON-based) ---
_add("nosql-operators",   4, rb'(?i)[\{\[]\s*"\$?(?:ne|gt|lt|in|nin|or|and|regex)"\s*:', 2)
_add("nosql-bool-op",     3, rb'(?i)"\$(?:or|and)"\s*:\s*\[', 2)
_add("nosql-regex",       3, rb'(?i)"\$(?:regex|where)"\s*:', 2)
_add("nosql-js",          3, rb'(?i)"\$(?:where)"\s*:\s*".*?(?:eval|Function|this)\b', 3)

# --- SSTI ---
_add("ssti-jinja",        4, rb'(?s)\{\{.*?\}\}', 2)
_add("ssti-twig",         3, rb'(?s)\{\%.*?\%\}', 2)
_add("ssti-velocity",     3, rb'(?s)\$\{.*?\}', 2)
_add("ssti-erb",          3, rb'(?s)<%=?\s*.*?%>', 2)
_add("ssti-handlebars",   3, rb'(?s)\{\{#?[^}]+\}\}', 2)
_add("ssti-liquid",       2, rb'(?s)\{\%-?.*?-?\%\}', 3)

# --- XXE / DTD ---
_add("xxe-doctype",       4, rb'(?is)<!DOCTYPE\b.*?(?:SYSTEM|PUBLIC)', 2)
_add("xxe-entity",        3, rb'(?is)<!ENTITY\b', 2)
_add("file-uri",          3, rb'(?i)\bfile://', 2)

# --- OS Command ---
_add("cmd-metachars",     5, rb'(?i)(?:;|\|\||&&|`|\$\()', 1)
_add("cmd-shells",        4, rb'(?i)\b(?:bash|sh|zsh|cmd\.exe|powershell|pwsh)\b', 2)
_add("cmd-tools",         3, rb'(?i)\b(?:nc|ncat|curl|wget|scp|ftp)\b', 2)

# --- LFI/RFI / Traversal ---
_add("traversal-dotdot",  5, rb'(?i)(?:\.\./)+', 1)
_add("traversal-enc",     4, rb'(?i)(?:%2e%2e%2f)+', 1)
_add("traversal-win",     4, rb'(?i)(?:\.\.\\)+', 1)
_add("lfi-linux",         4, rb'(?i)/(?:etc/passwd|proc/self/environ|proc/cpuinfo|proc/meminfo)', 1)
_add("lfi-win",           4, rb'(?i)\\(?:boot\.ini|windows\\win\.ini|win\.ini)\b', 1)
_add("rfi-wrappers",      4, rb'(?i)\b(?:php|file|data|zip|expect)://', 1)
_add("rfi-http",          2, rb'(?i)\bhttps?://[^ \t\r\n]+', 2)

# --- SSRF (localhost/IMDS/internal CIDR hedefleri) ---
_add("ssrf-localhost",    5, rb'(?i)\bhttps?://(?:localhost|127\.0\.0\.1|\[?::1\]?)\b', 2)
_add("ssrf-imds-aws",     5, rb'(?i)\bhttps?://169\.254\.169\.254\b', 2)
_add("ssrf-imds-gcp",     4, rb'(?i)\bhttp://metadata\.googleinternal\b', 2)
_add("ssrf-internal-cidr",4, rb'(?i)\bhttps?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)', 2)

# --- GraphQL introspection ---
_add("gql-introspection", 4, rb'(?i)__schema\b|__type\b|__typename\b', 2)

# --- LDAP injection (temel) ---
_add("ldap-filters",      3, rb'(?i)[\(\)]\s*(?:\|{2}|\&{2})\s*[\(\)]', 3)
_add("ldap-wildcards",    3, rb'(?i)\(\w+\s*=\s*\*.*\*\)', 3)

# --- Path poisoning / Null byte ---
_add("null-byte",         4, rb'(?i)%00', 1)
_add("path-poison",       3, rb'(?i)\b\.\w{1,4}\b\?.*\b\.\w{1,4}\b', 3)

# --- ReDoS-ish overly long token (heuristic) ---
_add("long-token",        2, rb'[A-Za-z0-9\+/_-]{256,}', 3)

# ===================== Scoring =====================
def _score_blob(blob: str) -> Tuple[int, List[str]]:
    total = 0
    hits: List[str] = []
    b = blob.encode('utf-8', 'ignore')
    for idx, (name, score, rx, pl) in enumerate(RULES, 1):
        if pl > PARANOIA_LEVEL:
            continue
        if rx.search(b):
            total += score
            hits.append(f"R{idx}:{name}(+{score})")
    # UTF-7 ipucu kaldıysa ufak katkı
    if "UTF7_HINT" in blob:
        total += 1
        hits.append("utf7-hint(+1)")
    return total, hits

# ===================== Policies / Utilities =====================
def _match_policy(path: str, method: str) -> dict:
    """
    PATH_POLICIES anahtarları birebir '/x' veya wildcard ('/api/*') ya da 'METHOD:/x' olabilir.
    Öncelik: 'METHOD:/exact' > 'METHOD:/wild*' > '/exact' > '/wild*'
    """
    candidates = []
    key_method_exact = f"{method}:{path}"
    key_exact = path

    if key_method_exact in PATH_POLICIES:
        return PATH_POLICIES[key_method_exact]
    # method+wildcards
    for k, v in PATH_POLICIES.items():
        if k.startswith(method + ":"):
            pat = k.split(":", 1)[1]
            if "*" in pat and fnmatch(path, pat):
                candidates.append(v)
    if candidates:
        return candidates[0]
    # path wildcards
    for k, v in PATH_POLICIES.items():
        if not (":" in k):
            if k == path:
                return v
            if "*" in k and fnmatch(path, k):
                return v
    return {}

def _param_policy_score(path: str, method: str, headers: Optional[Dict[str,str]], body: bytes) -> int:
    parsed = urllib.parse.urlsplit(path)
    key = f"{method}:{parsed.path}"
    pol = PARAM_POLICIES.get(key)
    if not pol: return 0
    score = 0
    # GET
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for k, rule in pol.items():
        if k == "_json": continue
        if k in qs:
            val = qs[k][0]
            if "max_len" in rule and len(val) > int(rule["max_len"]):
                score += PARAM_VIOLATION_SCORE
            if "regex" in rule and not re.fullmatch(rule["regex"], val or ""):
                score += PARAM_VIOLATION_SCORE
    # JSON
    if method == "POST" and pol.get("_json") and headers:
        ct = headers.get("Content-Type","")
        if ct.startswith("application/json"):
            raw = _decode_content(body or b"", headers or {})
            if len(raw) > pol["_json"].get("max_len", 4096):
                score += PARAM_VIOLATION_SCORE
            try:
                data = json.loads(raw.decode("utf-8","ignore"))
                for fld, typ in pol["_json"]["schema"].items():
                    ok = (isinstance(data.get(fld), str) if typ=="str"
                          else isinstance(data.get(fld), int) if typ=="int"
                          else fld in data)
                    if not ok:
                        score += PARAM_VIOLATION_SCORE
            except Exception:
                score += PARAM_VIOLATION_SCORE
    return score

# ===================== Main API =====================
def waf_ok_full(path: str, method: str, headers: Optional[Dict[str,str]], body: bytes) -> Tuple[bool, Optional[str]]:
    parsed = urllib.parse.urlsplit(path)
    has_input = bool(parsed.query) or (method == "POST" and body and len(body) > 0)

    if not WAF_ENABLED:
        return True, None
    if parsed.path in WHITELIST_PATHS:
        return True, None
    if WAF_ONLY_ON_INPUT and not has_input:
        return True, None

    # Honeypot
    for bait in HONEY_POTS:
        if parsed.path.startswith(bait):
            info = f"HONEYPOT:{bait}"
            return (True, "SHADOW:" + info) if WAF_SHADOW_MODE else (False, info)

    # Upload/multipart
    decoded_body = _decode_content(body or b"", headers or {})
    mp_issue = _check_multipart(headers or {}, decoded_body)
    if mp_issue:
        info = "UPLOAD:" + mp_issue
        return (True, "SHADOW:" + info) if (WAF_SHADOW_MODE) else (False, info)

    # Policy (per-path)
    pol = _match_policy(parsed.path, method)
    pl_saved, thr_saved = PARANOIA_LEVEL, SCORE_THRESHOLD
    action = pol.get("action", "block")  # block|allow|shadow
    try:
        globals()["PARANOIA_LEVEL"]  = int(pol.get("pl", PARANOIA_LEVEL))
        globals()["SCORE_THRESHOLD"] = int(pol.get("threshold", SCORE_THRESHOLD))

        blob = _normalize(method, path, decoded_body, headers if SCAN_HEADERS else None)
        score, hits = _score_blob(blob)
        pscore = _param_policy_score(path, method, headers, body)
        if pscore:
            score += pscore; hits.append(f"param-policy(+{pscore})")
    finally:
        globals()["PARANOIA_LEVEL"]  = pl_saved
        globals()["SCORE_THRESHOLD"] = thr_saved

    if score >= SCORE_THRESHOLD:
        info = f"SCORE={score} thr={SCORE_THRESHOLD}; hits=" + ",".join(hits[:10])
        if action == "allow" or WAF_SHADOW_MODE or action == "shadow":
            return True, "SHADOW:" + info
        return False, info
    return True, None

def waf_ok(path: str, method: str, body: bytes) -> Tuple[bool, Optional[str]]:
    # backward compatible
    return waf_ok_full(path, method, None, body)

# ===================== Config loader =====================
def load_config(cfg: dict):
    global WAF_ENABLED, WAF_ONLY_ON_INPUT, DEBUG_WAF, SCAN_HEADERS, PARANOIA_LEVEL
    global SCORE_THRESHOLD, WAF_SHADOW_MODE, WHITELIST_PATHS, HONEY_POTS, PATH_POLICIES
    global PARAM_POLICIES, PARAM_VIOLATION_SCORE, MAX_NORMALIZE_LOOPS, TRY_BASE64_DECODE
    global B64_MAX_LEN, MAX_UPLOAD_MB, FORBIDDEN_EXT

    WAF_ENABLED           = bool(cfg.get("waf_enabled", WAF_ENABLED))
    WAF_ONLY_ON_INPUT     = bool(cfg.get("waf_only_on_input", WAF_ONLY_ON_INPUT))
    DEBUG_WAF             = bool(cfg.get("waf_debug", DEBUG_WAF))
    SCAN_HEADERS          = bool(cfg.get("waf_scan_headers", SCAN_HEADERS))
    PARANOIA_LEVEL        = int(cfg.get("waf_paranoia", PARANOIA_LEVEL))
    SCORE_THRESHOLD       = int(cfg.get("waf_score_threshold", SCORE_THRESHOLD))
    WAF_SHADOW_MODE       = bool(cfg.get("waf_shadow_mode", WAF_SHADOW_MODE))

    WHITELIST_PATHS       = list(cfg.get("waf_whitelist_paths", WHITELIST_PATHS))
    HONEY_POTS            = list(cfg.get("waf_honeypots", HONEY_POTS))
    PATH_POLICIES         = dict(cfg.get("waf_path_policies", PATH_POLICIES))

    PARAM_POLICIES        = dict(cfg.get("waf_param_policies", PARAM_POLICIES))
    PARAM_VIOLATION_SCORE = int(cfg.get("waf_param_violation_score", PARAM_VIOLATION_SCORE))

    MAX_NORMALIZE_LOOPS   = int(cfg.get("waf_normalize_loops", MAX_NORMALIZE_LOOPS))
    TRY_BASE64_DECODE     = bool(cfg.get("waf_try_base64", TRY_BASE64_DECODE))
    B64_MAX_LEN           = int(cfg.get("waf_b64_max_len", B64_MAX_LEN))

    MAX_UPLOAD_MB         = int(cfg.get("waf_upload_max_mb", MAX_UPLOAD_MB))
    FORBIDDEN_EXT         = set(cfg.get("waf_forbidden_ext", list(FORBIDDEN_EXT)))