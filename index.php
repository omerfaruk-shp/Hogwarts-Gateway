<?php
// Hogwarts Gateway — WAF Test Panel (SAFE)
// Bu sayfa hiçbir payload'ı çalıştırmaz; sadece ekran metni olarak gösterir.
// Ama WAF ham isteği taradığı için gerçek saldırı kalıplarını engeller (406).
// LAB kilidi: dış ağda çalıştırmayı zorlaştırır (isteğe bağlı).
$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$is_local =
  $ip === '127.0.0.1' || $ip === '::1' ||
  preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/', $ip);
if (!$is_local && getenv('HOGWARTS_GATEWAY_LAB') !== '1') {
  http_response_code(403);
  header('Content-Type: text/plain; charset=UTF-8');
  exit("403 LAB only. Set HOGWARTS_GATEWAY_LAB=1 to force-enable.\n");
}

header('Content-Type: text/html; charset=UTF-8');
function esc($s){ return htmlspecialchars($s ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

$q   = $_GET['q']   ?? ''; // XSS test alanı
$cmd = $_GET['cmd'] ?? ''; // OS command imza alanı
$sql = $_GET['sql'] ?? ''; // SQLi imza alanı
?>
<!doctype html>
<html lang="tr">
<meta charset="utf-8">
<title>Hogwarts Gateway — WAF Test Paneli</title>
<style>
  body{font-family:system-ui, sans-serif; max-width: 900px; margin: 36px auto}
  .row{display:grid; grid-template-columns: 1fr 1fr; gap:14px}
  .card{border:1px solid #ddd; border-radius:10px; padding:14px}
  input,textarea{width:100%; font-family:ui-monospace, SFMono-Regular, Menlo, monospace}
  textarea{height:90px}
  .mono{font-family:ui-monospace, SFMono-Regular, Menlo, monospace; white-space:pre-wrap}
  small{color:#666}
</style>
<h1>Hogwarts Gateway — <em>WAF Test Paneli</em></h1>
<p class="mono">Bu panel saldırı payload'larını çalıştırmaz; sadece metin olarak gösterir.
WAF ham isteği tarar ve <strong>406</strong> ile engeller. Tarayıcı bazı karakterleri yüzdelediği için,
WAF'ta normalizasyon (URL/HTML decode) açık olmalıdır (senin Gateway’de bu var).</p>

<div class="row">
  <form class="card" method="get">
    <h3>XSS Test</h3>
    <small>Örn: &lt;script&gt;alert(1)&lt;/script&gt; veya &lt;img src=x onerror=alert(1)&gt;</small>
    <textarea name="q"><?= esc($q) ?></textarea>
    <button type="submit">Gönder</button>
    <p><strong>Gelen (escape edilmiş) içerik:</strong></p>
    <div class="mono"><?= esc($q) ?></div>
  </form>

  <form class="card" method="get">
    <h3>OS Komut İmzası Testi</h3>
    <small>Örn: <code>ls;id</code>, <code>whoami&&uname</code>, <code>$(id)</code>, <code>`id`</code></small>
    <input name="cmd" value="<?= esc($cmd) ?>">
    <button type="submit">Gönder</button>
    <p><strong>Gelen (escape edilmiş) içerik:</strong></p>
    <div class="mono"><?= esc($cmd) ?></div>
  </form>
</div>

<div class="row" style="margin-top:14px">
  <form class="card" method="get">
    <h3>SQLi İmzası Testi</h3>
    <small>Örn: <code>1' OR '1'='1 --</code>, <code>UNION SELECT 1,2</code>, <code>SLEEP(3)</code></small>
    <input name="sql" value="<?= esc($sql) ?>">
    <button type="submit">Gönder</button>
    <p><strong>Gelen (escape edilmiş) içerik:</strong></p>
    <div class="mono"><?= esc($sql) ?></div>
  </form>

  <div class="card">
    <h3>İpuçları</h3>
    <ul>
      <li>WAF blokladığında yanıt başlığında <code>X-HGWAF-Rule</code> görürsün (debug açıkken).</li>
      <li><code>curl</code> ile ham karakter gönderirsen (encode olmadan) daha net test edersin.</li>
      <li>Yanlış pozitif olursa WAF skor eşiğini yükselt veya ilgili endpoint’i whitelist’e al.</li>
    </ul>
  </div>
</div>
</html>
