<?php
/**
 * Hogwarts Gateway — WAF Test Panel
 *
 * This script provides a safe testing interface for Hogwarts Gateway's WAF.
 * - No payload is executed; all user inputs are HTML-escaped before output.
 * - The WAF operates on the raw HTTP request and blocks malicious patterns with a 406 response.
 * - Intended for local or lab use only.
 *
 * @license MIT
 */

// -----------------------------------------------------------------------------
// ACCESS CONTROL — LOCAL ONLY (unless LAB mode is enabled)
// -----------------------------------------------------------------------------
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
$isLocal  = (
    $clientIp === '127.0.0.1' ||
    $clientIp === '::1' ||
    preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/', $clientIp)
);

if (!$isLocal && getenv('HOGWARTS_GATEWAY_LAB') !== '1') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    exit("403 Forbidden — LAB mode only. Set HOGWARTS_GATEWAY_LAB=1 to enable.\n");
}

// -----------------------------------------------------------------------------
// HELPER FUNCTIONS
// -----------------------------------------------------------------------------
/**
 * Escape HTML special characters for safe output.
 *
 * @param string $value Input string
 * @return string Escaped string
 */
function esc(string $value): string {
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// -----------------------------------------------------------------------------
// CAPTURE TEST INPUTS
// -----------------------------------------------------------------------------
$q   = $_GET['q']   ?? ''; // XSS test input
$cmd = $_GET['cmd'] ?? ''; // OS command injection test input
$sql = $_GET['sql'] ?? ''; // SQL injection test input

// -----------------------------------------------------------------------------
// OUTPUT HTML
// -----------------------------------------------------------------------------
header('Content-Type: text/html; charset=UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Hogwarts Gateway — WAF Test Panel</title>
<style>
    body { font-family: system-ui, sans-serif; max-width: 900px; margin: 36px auto; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    .card { border: 1px solid #ddd; border-radius: 10px; padding: 14px; }
    input, textarea { width: 100%; font-family: ui-monospace, monospace; }
    textarea { height: 90px; }
    .mono { font-family: ui-monospace, monospace; white-space: pre-wrap; }
    small { color: #666; }
</style>
</head>
<body>

<h1>Hogwarts Gateway — <em>WAF Test Panel</em></h1>
<p class="mono">
    This panel does not execute any payload; all input is displayed as escaped text.<br>
    The WAF inspects the raw request and blocks malicious content with a <strong>406 Not Acceptable</strong> response.<br>
    For accurate testing, ensure that WAF normalization (URL/HTML decoding) is enabled.
</p>

<div class="row">
    <!-- XSS Test Form -->
    <form class="card" method="get">
        <h3>XSS Test</h3>
        <small>Example: &lt;script&gt;alert(1)&lt;/script&gt; or &lt;img src=x onerror=alert(1)&gt;</small>
        <textarea name="q"><?= esc($q) ?></textarea>
        <button type="submit">Submit</button>
        <p><strong>Escaped output:</strong></p>
        <div class="mono"><?= esc($q) ?></div>
    </form>

    <!-- OS Command Injection Test Form -->
    <form class="card" method="get">
        <h3>OS Command Injection Test</h3>
        <small>Example: <code>ls;id</code>, <code>whoami&&uname</code>, <code>$(id)</code>, <code>`id`</code></small>
        <input name="cmd" value="<?= esc($cmd) ?>">
        <button type="submit">Submit</button>
        <p><strong>Escaped output:</strong></p>
        <div class="mono"><?= esc($cmd) ?></div>
    </form>
</div>

<div class="row" style="margin-top:14px">
    <!-- SQL Injection Test Form -->
    <form class="card" method="get">
        <h3>SQL Injection Test</h3>
        <small>Example: <code>1' OR '1'='1 --</code>, <code>UNION SELECT 1,2</code>, <code>SLEEP(3)</code></small>
        <input name="sql" value="<?= esc($sql) ?>">
        <button type="submit">Submit</button>
        <p><strong>Escaped output:</strong></p>
        <div class="mono"><?= esc($sql) ?></div>
    </form>

    <!-- Tips Card -->
    <div class="card">
        <h3>Tips</h3>
        <ul>
            <li>When blocked, check the <code>X-HGWAF-Rule</code> response header (debug mode).</li>
            <li>Use <code>curl</code> for raw payload tests without browser encoding.</li>
            <li>Adjust WAF score threshold or whitelist paths to reduce false positives.</li>
        </ul>
    </div>
</div>

</body>
</html>
