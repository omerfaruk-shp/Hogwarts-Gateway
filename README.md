# Hogwarts-Gateway
Hogwarts Gateway — A Python-based HTTP server with an integrated Web Application Firewall (WAF). Blocks XSS, SQL Injection, OS Command Injection, Path Traversal, and dozens of other attack vectors. Fully configurable, high-security, and lightweight.

<!-- README.md (HTML-flavored) -->
<h1 align="center">🏰 Hogwarts Gateway</h1>
<p align="center">
  <strong>A Python-based HTTP server with an integrated Web Application Firewall (WAF)</strong><br/>
  Blocks XSS, SQL Injection, OS Command Injection, Path Traversal, LFI/RFI, NoSQLi, SSTI, XXE, SSRF, and more.
</p>
<p align="center">
  <em>The magical shield for your web applications.</em> 🪄
</p>

<hr/>

<h2>✨ Features</h2>
<ul>
  <li><strong>Integrated WAF (ULTRA)</strong> – rich signature set, anomaly scoring, paranoia levels, header scanning.</li>
  <li><strong>Shadow mode</strong>, per-path policies, honeypots, base64/URL/HTML normalization.</li>
  <li><strong>Multipart upload controls</strong> – forbidden extensions, basic magic-number checks, size limits.</li>
  <li><strong>Rate limiting &amp; temporary bans</strong> – token bucket + fail2ban-like counters.</li>
  <li><strong>PHP-CGI support</strong> – run <code>.php</code> scripts via <code>php-cgi</code>.</li>
  <li><strong>Secure defaults</strong> – CSP, XFO, X-CTO, Referrer-Policy, Permissions-Policy.</li>
  <li><strong>Config-driven</strong> – JSON config with CLI overrides.</li>
  <li><strong>Lightweight</strong> – no external dependencies for the core.</li>
</ul>

<h2>🏗️ Architecture</h2>
<ul>
  <li><code>hogwarts_server.py</code> – HTTP server, static &amp; PHP handling, rate/ban, HTML error pages.</li>
  <li><code>hogwarts_waf.py</code> – WAF engine (normalization, signatures, policies, scoring).</li>
  <li><code>config.json</code> – central configuration (server + WAF).</li>
  <li><code>www/</code> – document root (your app content).</li>
</ul>

<h2>🚀 Quick Start</h2>
<pre><code class="language-bash">git clone https://github.com/&lt;your-username&gt;/Hogwarts-Gateway.git
cd Hogwarts-Gateway

# Create docroot and a simple PHP page
mkdir -p www
printf '&lt;?php echo "Hogwarts Gateway OK "; echo phpversion(); ?&gt;' &gt; www/index.php

# (Debian/Ubuntu) Install php-cgi
sudo apt update &amp;&amp; sudo apt install -y php-cgi

# Run with defaults (or pass --config config.json)
python3 hogwarts_server.py --host 0.0.0.0 --port 8080 --docroot ./www --php-cgi "$(which php-cgi)"
</code></pre>

<p>Test:</p>
<pre><code class="language-bash">curl -i http://127.0.0.1:8080/index.php
# WAF should block these (returns 406):
curl -i "http://127.0.0.1:8080/index.php?q=&lt;script&gt;alert(1)&lt;/script&gt;"
curl -i "http://127.0.0.1:8080/index.php?cmd=ls;id"
</code></pre>

<h2>⚙️ Configuration</h2>
<p>All settings can be managed via <code>config.json</code> and/or CLI flags. A strong baseline config:</p>
<pre><code class="language-json">{
  "host": "0.0.0.0",
  "port": 8080,
  "docroot": "./www",
  "php_cgi": "/usr/bin/php-cgi",

  "rate": 10,
  "burst": 20,
  "ban_threshold": 20,
  "ban_window": 60,
  "ban_duration": 300,
  "auto_index": false,
  "php_timeout": 30,

  "waf_enabled": true,
  "waf_only_on_input": false,
  "waf_debug": true,
  "waf_scan_headers": true,
  "waf_paranoia": 3,
  "waf_score_threshold": 8,
  "waf_shadow_mode": false,
  "waf_whitelist_paths": [],
  "waf_honeypots": ["/wp-admin", "/phpmyadmin", "/.env", "/.git"],

  "waf_path_policies": {
    "POST:/login": { "pl": 3, "threshold": 6, "action": "block" },
    "/upload":     { "pl": 3, "threshold": 6, "action": "block" },
    "/healthz":    { "pl": 1, "threshold": 999, "action": "allow" }
  },

  "waf_param_policies": {
    "GET:/search": {
      "q": { "max_len": 128, "regex": "^[\\w\\s\\-\\.,]{0,128}$" }
    },
    "POST:/api/login": {
      "_json": { "schema": { "user": "str", "pass": "str" }, "max_len": 2048 }
    }
  },

  "waf_param_violation_score": 3,
  "waf_normalize_loops": 2,
  "waf_try_base64": true,
  "waf_b64_max_len": 4096,
  "waf_upload_max_mb": 16,
  "waf_forbidden_ext": [".php",".php3",".php4",".php5",".phtml",".phar",".cgi",".fcgi",".jsp",".asp",".aspx",".js",".mjs",".exe",".dll",".so",".sh",".bat",".cmd",".vbs",".ps1"]
}
</code></pre>

<p><strong>Apply config at startup:</strong></p>
<pre><code class="language-bash">python3 hogwarts_server.py --config config.json
</code></pre>

<h2>🧪 Safe WAF Testing</h2>
<p>Use harmless inputs that trigger signatures but do not execute on the server (never deploy intentional vulnerabilities). Example:</p>
<pre><code class="language-bash"># XSS signature
curl -i "http://127.0.0.1:8080/index.php?q=&lt;img src=x onerror=alert(1)&gt;"
# OS command signature
curl -i "http://127.0.0.1:8080/index.php?cmd=whoami&&id"
# SQLi signature
curl -i "http://127.0.0.1:8080/index.php?u=1' OR '1'='1 --"
</code></pre>
<p>If <code>waf_debug</code> is on, responses include <code>X-HGWAF-Rule</code> (or <code>X-HGWAF-Shadow</code> in shadow mode) indicating matched rules.</p>

<h2>🛡️ Security Notes</h2>
<ul>
  <li>Run behind a reverse proxy for TLS (e.g., Nginx/Caddy) or terminate TLS externally.</li>
  <li>Keep <code>php-cgi</code> updated; consider php-fpm/fastcgi for heavy workloads.</li>
  <li>Honeypot paths are aggressive; expect to catch bots quickly (possible false positives).</li>
  <li>Adjust <code>waf_score_threshold</code> and path policies per your app to balance false positives.</li>
  <li>Always test in a staging environment before production changes.</li>
</ul>

<h2>📂 Project Structure</h2>
<pre><code>Hogwarts-Gateway/
├─ hogwarts_server.py
├─ hogwarts_waf.py
├─ config.json
└─ www/
   └─ index.php
</code></pre>

<h2>🖥️ CLI Flags (excerpt)</h2>
<pre><code class="language-bash">python3 hogwarts_server.py \
  --host 0.0.0.0 --port 8080 --docroot ./www --php-cgi /usr/bin/php-cgi \
  --waf-enabled true --waf-scan-headers true --waf-paranoia 3 --waf-score-threshold 8
</code></pre>

<h2>🧩 Roadmap</h2>
<ul>
  <li>Optional FastCGI / php-fpm backend</li>
  <li>Metrics endpoint (Prometheus)</li>
  <li>Rule packs &amp; auto-updates</li>
  <li>Config hot-reload</li>
</ul>

<h2>🤝 Contributing</h2>
<p>Issues and PRs are welcome. Please include reproduction steps and configuration snippets when reporting WAF behavior.</p>

<h2>📜 License</h2>
<p>MIT. See <code>LICENSE</code>.</p>

<hr/>

<p align="center">
  Built with 🐍 Python. Guarded by 🏰 Hogwarts WAF.
</p>
