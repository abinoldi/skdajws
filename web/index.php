<?php
/**
 * Single-file AntiBot + Panel + Settings (index.php)
 * - Panel : /index.php?panel[&secret=...]
 * - Setting : /index.php?set[&secret=...] (form, ada tombol Back)
 * - Reset : tombol di panel (hapus log)
 * - Custom Blocked IPs: Settings → Blocked IPs
 * - Custom Blocked ASNs: Settings → Blocked ASNs
 * 
 * Files otomatis:
 * - antibot_config.json
 * - visitor_logs.jsonl (JSON Lines)
 * - blocked_ips.json
 * - blocked_asns.json
 */

declare(strict_types=1);

// =============================
// Paths & defaults
// =============================
$CONFIG_FILE = __DIR__ . '/antibot_config.json';
$LOG_FILE = __DIR__ . '/visitor_logs.jsonl';
$BLOCKED_IPS_FILE = __DIR__ . '/blocked_ips.json';
$BLOCKED_ASNS_FILE = __DIR__ . '/blocked_asns.json'; // ✅ NEW: File untuk ASN yang diblokir

$defaultConfig = [
    'rapidapi_key' => 'YOUR_RAPIDAPI_KEY', // NetDetective
    'ipinfo_token' => 'YOUR_IPINFO_TOKEN', // IPinfo Lite token
    'target_human' => 'https://example.com',
    'target_bot' => 'https://www.google.com',
    'panel_secret' => '',
    'log_tail_limit' => 30,
];

// =============================
// Config helpers
// =============================
function load_config(string $path, array $defaults): array {
    if (!file_exists($path)) {
        file_put_contents($path, json_encode($defaults, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES), LOCK_EX);
        return $defaults;
    }
    $raw = file_get_contents($path);
    $cfg = json_decode($raw ?: '', true);
    if (!is_array($cfg)) $cfg = [];
    return array_merge($defaults, $cfg);
}

function save_config(string $path, array $cfg): void {
    file_put_contents($path, json_encode($cfg, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES), LOCK_EX);
}

// =============================
// Blocked IPs helpers
// =============================
function load_blocked_ips(string $path): array {
    if (!file_exists($path)) {
        file_put_contents($path, json_encode([], JSON_PRETTY_PRINT));
        return [];
    }
    $raw = file_get_contents($path);
    $ips = json_decode($raw ?: '', true);
    return is_array($ips) ? $ips : [];
}

function save_blocked_ips(string $path, array $ips): void {
    file_put_contents($path, json_encode($ips, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function is_ip_blocked(string $ip, array $blocked_ips): bool {
    foreach ($blocked_ips as $blocked_ip) {
        if (strpos($blocked_ip, '/') !== false) {
            // CIDR notation
            if (cidr_match($ip, $blocked_ip)) {
                return true;
            }
        } else {
            // Exact IP match
            if ($ip === $blocked_ip) {
                return true;
            }
        }
    }
    return false;
}

function cidr_match(string $ip, string $cidr): bool {
    list($subnet, $mask) = explode('/', $cidr);
    $mask = (int)$mask;
    
    if ($mask < 0 || $mask > 32) return false;
    
    $ip_long = ip2long($ip);
    $subnet_long = ip2long($subnet);
    
    if ($ip_long === false || $subnet_long === false) return false;
    
    $mask_long = -1 << (32 - $mask);
    $subnet_long &= $mask_long;
    
    return ($ip_long & $mask_long) === $subnet_long;
}

// ✅ NEW: Blocked ASNs helpers
function load_blocked_asns(string $path): array {
    if (!file_exists($path)) {
        file_put_contents($path, json_encode([], JSON_PRETTY_PRINT));
        return [];
    }
    $raw = file_get_contents($path);
    $asns = json_decode($raw ?: '', true);
    return is_array($asns) ? $asns : [];
}

function save_blocked_asns(string $path, array $asns): void {
    file_put_contents($path, json_encode($asns, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function is_asn_blocked(string $asn, array $blocked_asns): bool {
    return in_array($asn, $blocked_asns, true);
}

$config = load_config($CONFIG_FILE, $defaultConfig);
$blocked_ips = load_blocked_ips($BLOCKED_IPS_FILE);
$blocked_asns = load_blocked_asns($BLOCKED_ASNS_FILE); // ✅ NEW: Load blocked ASNs

// =============================
// Guards
// =============================
function require_secret_if_set(array $config): void {
    if (!empty($config['panel_secret'])) {
        $given = $_GET['secret'] ?? '';
        if (!hash_equals((string)$config['panel_secret'], (string)$given)) {
            http_response_code(403);
            echo "<meta charset='utf-8'><h3>Forbidden</h3><p>Panel requires ?secret=...</p>";
            exit;
        }
    }
}

// =============================
// Utils
// =============================
function h($s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

function client_ip(): string {
    $headers = ['HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP','HTTP_CLIENT_IP','REMOTE_ADDR'];
    foreach ($headers as $h) {
        if (!empty($_SERVER[$h])) {
            $val = $_SERVER[$h];
            if ($h === 'HTTP_X_FORWARDED_FOR' && strpos($val, ',') !== false) {
                $parts = array_map('trim', explode(',', $val));
                return $parts[0];
            }
            return $val;
        }
    }
    return '0.0.0.0';
}

function is_bot_by_ua(string $ua): bool {
    $ua = strtolower($ua);
    $bots = [
        'bot','spider','crawl','slurp','curl','wget','python-requests','java','libwww',
        'facebookexternalhit','whatsapp','telegrambot','pingdom','ahrefs','semrush',
        'screaming frog','gtmetrix','google-structured-data-testing-tool','headless'
    ];
    foreach ($bots as $b) if (strpos($ua, $b) !== false) return true;
    return false;
}

// IPinfo Lite (ASN & Country)
function ipinfo_lite(?string $token, string $ip, int $timeout=5): array {
    if (!$token) return ['asn'=>'','as_name'=>'','country_code'=>'','country'=>''];
    $url = "https://api.ipinfo.io/lite/".rawurlencode($ip)."?token=".rawurlencode($token);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    ]);
    $resp = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    if ($err || !$resp) return ['asn'=>'','as_name'=>'','country_code'=>'','country'=>''];
    $j = json_decode($resp, true);
    if (!is_array($j)) return ['asn'=>'','as_name'=>'','country_code'=>'','country'=>''];
    return [
        'asn' => (string)($j['asn'] ?? ''),
        'as_name' => (string)($j['as_name'] ?? ''),
        'country_code' => (string)($j['country_code'] ?? ''),
        'country' => (string)($j['country'] ?? ''),
    ];
}

// RapidAPI NetDetective (verdict)
function call_netdetective(string $apiKey, string $ip, int $timeout = 5): array {
    if (!$apiKey) return ['error' => 'Missing RapidAPI key'];
    $url = "https://netdetective.p.rapidapi.com/query?ipaddress=" . rawurlencode($ip);
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => '',
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_CUSTOMREQUEST => 'GET',
        CURLOPT_HTTPHEADER => [
            'x-rapidapi-host: netdetective.p.rapidapi.com',
            'x-rapidapi-key: ' . $apiKey
        ],
    ]);
    $response = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    if ($err) return ['error' => "cURL Error: $err"];
    $json = json_decode($response ?: '', true);
    if (!is_array($json)) return ['error' => 'Invalid JSON response', 'raw' => $response];
    return $json;
}

function classify_from_api(array $api): array {
    $result = $api['result'] ?? $api;
    if (!is_array($result)) $result = [];
    $badFlags = [
        'isVpn','isDataCenter','isBruteForce','isSpam','isBogon',
        'isProxyHttp','isProxySocks','isProxyWeb','isProxyOther',
        'isSmtpRelay','isWebVuln','isNoMail','isZombie','isPotentialZombie',
        'isDynamic','isNoServer','isBadConf','isDDos','isOpenDns',
        'isCompromised','isWorm','isIrcDrone'
    ];
    $bad=false;
    foreach($badFlags as $f){
        if(!empty($result[$f])){
            $bad=true;
            break;
        }
    }
    return ['verdict'=>$bad?'bot':'human'];
}

function log_visit(string $path, array $row): void {
    file_put_contents($path, json_encode($row, JSON_UNESCAPED_SLASHES).PHP_EOL, FILE_APPEND|LOCK_EX);
}

function read_all_logs(string $path): array {
    if (!file_exists($path)) return [];
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $out = [];
    foreach ($lines as $ln) {
        $obj = json_decode($ln, true);
        if (is_array($obj)) $out[] = $obj;
    }
    return $out;
}

// helper: semua log by verdict (tanpa limit)
function read_logs_by_verdict_all(string $path, string $verdict): array {
    $all = read_all_logs($path);
    return array_values(array_filter($all, fn($r) => strtolower($r['verdict'] ?? '') === strtolower($verdict)));
}

function stats_from_logs(string $path): array {
    $all = read_all_logs($path);
    $total= count($all);
    $human=0;
    $bot=0;
    $byDay=[];
    $today=gmdate('Y-m-d');
    $month=gmdate('Y-m');
    $year=gmdate('Y');
    $views_today=0;
    $views_month=0;
    $views_year=0;
    $human_today=0;
    $bot_today=0;
    foreach($all as $r){
        $d = substr((string)($r['time'] ?? ''),0,10);
        if($d){
            $byDay[$d]=($byDay[$d]??0)+1;
        }
        $v = $r['verdict'] ?? '';
        if($v==='human') $human++;
        if($v==='bot') $bot++;
        if($d===$today){
            $views_today++;
            if($v==='human') $human_today++;
            if($v==='bot') $bot_today++;
        }
        if(substr($d,0,7)===$month) $views_month++;
        if(substr($d,0,4)===$year) $views_year++;
    }
    $avg_per_day = count($byDay)?(int)round(array_sum($byDay)/count($byDay)):0;
    return [
        'total'=>$total,'human'=>$human,'bot'=>$bot,
        'views_today'=>$views_today,'views_month'=>$views_month,'views_year'=>$views_year,
        'avg_per_day'=>$avg_per_day,
        'human_today'=>$human_today,'bot_today'=>$bot_today,
    ];
}

// =============================
// Settings
// =============================
if (isset($_GET['set'])) {
    require_secret_if_set($config);
    
    // ✅ NEW: Handle Blocked ASNs management
    if (isset($_POST['add_blocked_asn'])) {
        $new_asn = trim($_POST['new_asn'] ?? '');
        if ($new_asn && !in_array($new_asn, $blocked_asns)) {
            $blocked_asns[] = $new_asn;
            save_blocked_asns($BLOCKED_ASNS_FILE, $blocked_asns);
        }
        header("Location: ?set".(!empty($config['panel_secret'])?"&secret=".rawurlencode($config['panel_secret']):""));
        exit;
    }
    
    if (isset($_GET['delete_asn'])) {
        $asn_to_delete = $_GET['delete_asn'];
        $blocked_asns = array_filter($blocked_asns, fn($asn) => $asn !== $asn_to_delete);
        save_blocked_asns($BLOCKED_ASNS_FILE, array_values($blocked_asns));
        header("Location: ?set".(!empty($config['panel_secret'])?"&secret=".rawurlencode($config['panel_secret']):""));
        exit;
    }
    
    // Handle Blocked IPs management
    if (isset($_POST['add_blocked_ip'])) {
        $new_ip = trim($_POST['new_ip'] ?? '');
        if ($new_ip && !in_array($new_ip, $blocked_ips)) {
            $blocked_ips[] = $new_ip;
            save_blocked_ips($BLOCKED_IPS_FILE, $blocked_ips);
        }
        header("Location: ?set".(!empty($config['panel_secret'])?"&secret=".rawurlencode($config['panel_secret']):""));
        exit;
    }
    
    if (isset($_GET['delete_ip'])) {
        $ip_to_delete = $_GET['delete_ip'];
        $blocked_ips = array_filter($blocked_ips, fn($ip) => $ip !== $ip_to_delete);
        save_blocked_ips($BLOCKED_IPS_FILE, array_values($blocked_ips));
        header("Location: ?set".(!empty($config['panel_secret'])?"&secret=".rawurlencode($config['panel_secret']):""));
        exit;
    }
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['add_blocked_ip']) && !isset($_POST['add_blocked_asn'])) {
        $config['rapidapi_key'] = trim($_POST['rapidapi_key'] ?? $config['rapidapi_key']);
        $config['ipinfo_token'] = trim($_POST['ipinfo_token'] ?? $config['ipinfo_token']);
        $config['target_human'] = trim($_POST['target_human'] ?? $config['target_human']);
        $config['target_bot'] = trim($_POST['target_bot'] ?? $config['target_bot']);
        $config['panel_secret'] = trim($_POST['panel_secret'] ?? $config['panel_secret']);
        $config['log_tail_limit'] = max(5, (int)($_POST['log_tail_limit'] ?? $config['log_tail_limit']));
        save_config($CONFIG_FILE, $config);
        header("Location: ?panel".(!empty($config['panel_secret'])?"&secret=".rawurlencode($config['panel_secret']):""));
        exit;
    }
    
    echo "<meta charset='utf-8'><title>Settings</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <style>
    :root{ --muted:#cbd5e1; --text:#e5e7eb; --border:rgba(255,255,255,.18); --accent:#22d3ee; }
    *{box-sizing:border-box}
    body{margin:0;color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial}
    #bgvid{position:fixed;inset:0;width:100vw;height:100vh;object-fit:cover;z-index:-2;filter:brightness(.97);}
    .overlay{position:fixed;inset:0;background:linear-gradient(180deg,rgba(0,0,0,.04),rgba(0,0,0,.10));z-index:-1;}
    .wrap{max-width:880px;margin:0 auto;padding:20px}
    .title{display:flex;align-items:center;gap:10px;margin-bottom:16px}
    .dot{width:26px;height:26px;border-radius:999px;background:var(--accent)}
    .card{background:rgba(15,17,26,.22);backdrop-filter:blur(10px);border:1px solid var(--border);border-radius:14px;padding:16px}
    label{display:block;margin:10px 0 6px;color:var(--muted);font-size:13px}
    input{width:100%;background:rgba(7,8,12,.38);border:1px solid var(--border);border-radius:10px;padding:10px 12px;color:var(--text)}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .actions{display:flex;gap:10px;margin-top:16px;justify-content:space-between}
    a.btn,button{background:rgba(15,23,42,.6);backdrop-filter:blur(8px);color:var(--text);border:1px solid var(--border);border-radius:10px;padding:10px 14px;text-decoration:none;font-size:13px}
    a.btn:hover,button:hover{background:rgba(17,24,39,.7)}
    .ip-list{margin-top:16px;max-height:200px;overflow-y:auto;border:1px solid var(--border);border-radius:10px;padding:12px;background:rgba(7,8,12,.38)}
    .ip-item{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.1)}
    .ip-item:last-child{border-bottom:none}
    .delete-btn{color:#f87171;text-decoration:none;font-size:12px}
    .delete-btn:hover{color:#ef4444}
    </style>
    <video id='bgvid' autoplay muted loop playsinline preload='auto' src='https://motionbgs.com/media/1046/emily-in-the-cyberpunk-city.960x540.mp4'></video>
    <div class='overlay'></div>
    <div class='wrap'>
        <div class='title'><div class='dot'></div><h2 style='margin:0'>Antibot Settings</h2></div>
        
        <form method='post' class='card'>
            <div class='grid'>
                <div><label>RapidAPI Key (NetDetective)</label><input name='rapidapi_key' value='".h($config['rapidapi_key'])."'/></div>
                <div><label>IPinfo Token (Lite)</label><input name='ipinfo_token' value='".h($config['ipinfo_token'])."'/></div>
                <div><label>Target Human (redirect)</label><input name='target_human' value='".h($config['target_human'])."'/></div>
                <div><label>Target Bot (redirect)</label><input name='target_bot' value='".h($config['target_bot'])."'/></div>
                <div><label>Panel Secret (opsional)</label><input name='panel_secret' value='".h($config['panel_secret'])."'/></div>
                <div><label>Max Log Rows (panel)</label><input type='number' min='5' name='log_tail_limit' value='".(int)$config['log_tail_limit']."'/></div>
            </div>
            <div class='actions'>
                <a class='btn' href='?panel".(!empty($config['panel_secret'])?"&secret=".rawurlencode($config['panel_secret']):"")."'>← Back to Panel</a>
                <div><button type='submit'>Save Settings</button></div>
            </div>
        </form>
        
        <div class='card' style='margin-top:16px'>
            <h3 style='margin-top:0'>Blocked IPs</h3>
            <p style='color:var(--muted);font-size:13px;margin-top:0'>IP yang diblokir akan otomatis dianggap bot dan di-redirect ke target_bot</p>
            
            <form method='post'>
                <label>Add IP/CIDR (contoh: 192.168.1.1 atau 192.168.1.0/24)</label>
                <input name='new_ip' placeholder='192.168.1.1 atau 192.168.1.0/24' required/>
                <div class='actions'>
                    <button type='submit' name='add_blocked_ip'>Add Blocked IP</button>
                </div>
            </form>
            
            <div class='ip-list'>
                <label>Currently Blocked IPs/CIDRs:</label>
                ".($blocked_ips ? 
                    implode('', array_map(function($ip) use ($config) {
                        $secretQS = !empty($config['panel_secret']) ? "&secret=".rawurlencode($config['panel_secret']) : "";
                        return "<div class='ip-item'>
                            <span>".h($ip)."</span>
                            <a href='?set{$secretQS}&delete_ip=".rawurlencode($ip)."' class='delete-btn' onclick='return confirm(\"Hapus IP ".h($ip)." dari daftar blokir?\")'>Delete</a>
                        </div>";
                    }, $blocked_ips))
                    : "<div style='color:var(--muted);text-align:center;padding:20px'>No blocked IPs</div>"
                )."
            </div>
        </div>
        
        <!-- ✅ NEW: Blocked ASNs Section -->
        <div class='card' style='margin-top:16px'>
            <h3 style='margin-top:0'>Blocked ASNs</h3>
            <p style='color:var(--muted);font-size:13px;margin-top:0'>ASN yang diblokir akan otomatis di-redirect ke target_bot dan IP-nya disimpan di blocked_ips.json</p>
            
            <form method='post'>
                <label>Add ASN (contoh: AS8075 untuk Microsoft)</label>
                <input name='new_asn' placeholder='AS8075' required/>
                <div class='actions'>
                    <button type='submit' name='add_blocked_asn'>Add Blocked ASN</button>
                </div>
            </form>
            
            <div class='ip-list'>
                <label>Currently Blocked ASNs:</label>
                ".($blocked_asns ? 
                    implode('', array_map(function($asn) use ($config) {
                        $secretQS = !empty($config['panel_secret']) ? "&secret=".rawurlencode($config['panel_secret']) : "";
                        return "<div class='ip-item'>
                            <span>".h($asn)."</span>
                            <a href='?set{$secretQS}&delete_asn=".rawurlencode($asn)."' class='delete-btn' onclick='return confirm(\"Hapus ASN ".h($asn)." dari daftar blokir?\")'>Delete</a>
                        </div>";
                    }, $blocked_asns))
                    : "<div style='color:var(--muted);text-align:center;padding:20px'>No blocked ASNs</div>"
                )."
            </div>
        </div>
    </div>";
    exit;
}

// =============================
// Panel (BAR per-menit + pagination per 10)
// =============================
if (isset($_GET['panel'])) {
    require_secret_if_set($config);
    
    if (isset($_POST['reset_logs'])) {
        @unlink($LOG_FILE);
        touch($LOG_FILE);
        header("Location: ?panel".(!empty($config['panel_secret'])?"&secret=".rawurlencode($config['panel_secret']):""));
        exit;
    }
    
    if (isset($_GET['download'])) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="visitor_logs.jsonl"');
        readfile($LOG_FILE);
        exit;
    }
    
    $stats = stats_from_logs($LOG_FILE);
    
    // ===== Aggregate per MENIT: net = (#human) - (#bot) per 'Y-m-d H:i' =====
    $events = read_all_logs($LOG_FILE);
    $minuteNet = []; // key: 'Y-m-d H:i' => int(net)
    foreach ($events as $ev) {
        $t = (string)($ev['time'] ?? '');
        if (strlen($t) < 16) continue;
        $mkey = substr($t, 0, 16); // 'Y-m-d H:i'
        $ver = strtolower($ev['verdict'] ?? '');
        $delta = ($ver === 'human') ? 1 : (($ver === 'bot') ? -1 : 0);
        if (!isset($minuteNet[$mkey])) $minuteNet[$mkey] = 0;
        $minuteNet[$mkey] += $delta;
    }
    ksort($minuteNet); // urut naik waktu
    
    // Ambil hanya menit terakhir (misal 360 = 6 jam)
    $minutesMax = 360;
    $allKeys = array_keys($minuteNet);
    $allVals = array_values($minuteNet);
    if (count($allKeys) > $minutesMax) {
        $allKeys = array_slice($allKeys, -$minutesMax);
        $allVals = array_slice($allVals, -$minutesMax);
    }
    
    // Siapkan labels (HH:MM) & values
    $labels = [];
    $values = [];
    foreach ($allKeys as $i => $k) {
        $labels[] = substr($k, 11, 5); // 'HH:MM'
        $values[] = (int)$allVals[$i];
    }
    if (!$labels) {
        $labels = ['—'];
        $values = [0];
    }
    
    // ===== Recent Humans/Bots (NEWEST FIRST) dengan PAGINATION 10/baris =====
    $rowsHumAll = read_logs_by_verdict_all($LOG_FILE, 'human');
    $rowsBotAll = read_logs_by_verdict_all($LOG_FILE, 'bot');
    
    // newest first: data disimpan urutan lama→baru, jadi dibalik
    $rowsHum = array_reverse($rowsHumAll);
    $rowsBot = array_reverse($rowsBotAll);
    
    // Pagination params
    $perPage = 10;
    $secretQS = !empty($config['panel_secret']) ? "&secret=".rawurlencode($config['panel_secret']) : "";
    $panelBase = '?panel' . $secretQS;
    
    // Humans
    $humTotal = count($rowsHum);
    $humPages = max(1, (int)ceil($humTotal / $perPage));
    $humPage = max(1, min((int)($_GET['ph'] ?? 1), $humPages));
    $humStartIndex = ($humPage - 1) * $perPage;
    $humSlice = array_slice($rowsHum, $humStartIndex, $perPage);
    
    // Bots
    $botTotal = count($rowsBot);
    $botPages = max(1, (int)ceil($botTotal / $perPage));
    $botPage = max(1, min((int)($_GET['pb'] ?? 1), $botPages));
    $botStartIndex = ($botPage - 1) * $perPage;
    $botSlice = array_slice($rowsBot, $botStartIndex, $perPage);
    
    // Slider setup (window default 60 menit)
    $windowDefault = 60;
    $max_slider = max(0, count($labels) - $windowDefault);
    $startIndex = max(0, count($labels) - $windowDefault);
    
    // Pass ke JS
    $labels_js = json_encode($labels);
    $values_js = json_encode($values);
    
    echo "<meta charset='utf-8'>
    <title>Antibot Panel</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <style>
    :root{ --muted:#cbd5e1; --text:#e5e7eb; --border:rgba(255,255,255,.18); --accent:#22d3ee; }
    *{box-sizing:border-box}
    body{margin:0;color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial}
    #bgvid{position:fixed;inset:0;width:100vw;height:100vh;object-fit:cover;z-index:-2;filter:brightness(.95);}
    .overlay{position:fixed;inset:0;background:linear-gradient(180deg,rgba(0,0,0,.06),rgba(0,0,0,.12));z-index:-1;}
    .wrap{max-width:1100px;margin:0 auto;padding:18px;position:relative}
    header{position:sticky;top:0;z-index:10;background:rgba(7,9,14,.45);backdrop-filter:saturate(180%) blur(10px);border-bottom:1px solid var(--border)}
    header .inner{display:flex;align-items:center;justify-content:space-between;padding:12px 18px}
    .brand{display:flex;align-items:center;gap:10px}
    .dot{width:26px;height:26px;border-radius:999px;background:var(--accent)}
    .toolbar{display:flex;gap:10px}
    .btn,button{background:rgba(15,23,42,.6);backdrop-filter:blur(8px);color:var(--text);border:1px solid var(--border);border-radius:10px;padding:8px 12px;text-decoration:none;font-size:13px}
    .btn:hover,button:hover{background:rgba(17,24,39,.7)}
    .cards{display:grid;grid-template-columns: repeat(3, 1fr);gap:12px;margin-top:16px}
    .card{background:rgba(15,17,26,.24);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border:1px solid var(--border);border-radius:14px;padding:16px}
    .kpi-label{font-size:12px;color:#a1a1aa;margin-bottom:6px}
    .kpi-value{font-size:26px;font-weight:700}
    .panel{background:rgba(12,14,20,.28);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);border:1px solid var(--border);border-radius:14px;padding:16px;margin-top:14px}
    .panel-title{font-size:14px;color:#a1a1aa;display:flex;align-items:center;justify-content:space-between}
    .chart{height:320px;margin-top:10px}
    .logs-wrap{max-height:340px;overflow:auto;border:1px solid var(--border);border-radius:12px;background:rgba(10,12,18,.22);backdrop-filter:blur(8px)}
    table{width:100%;border-collapse:collapse;margin-top:10px}
    th,td{border-top:1px solid rgba(255,255,255,.08);padding:10px;font-size:13px;vertical-align:top}
    th{color:#a1a1aa;text-align:left;background:rgba(255,255,255,.03)}
    .tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--border)}
    .ok{background:rgba(34,197,94,.12);color:#86efac}
    .bad{background:rgba(239,68,68,.12);color:#fca5a5}
    @media (max-width:900px){ .cards{grid-template-columns:1fr} }
    .muted{color:#cbd5e1;font-size:12px}
    .slider-wrap{display:flex;align-items:center;gap:10px;margin-top:8px}
    .slider-wrap input[type=range]{width:100%}
    .blocked-ips-section{margin-top:16px}
    .blocked-ips-list{max-height:120px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;padding:8px;background:rgba(7,8,12,.38);margin-top:8px}
    .blocked-ip-item{display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:12px;border-bottom:1px solid rgba(255,255,255,.05)}
    .blocked-ip-item:last-child{border-bottom:none}
    </style>
    <!-- Chart.js + zoom -->
    <script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js'></script>
    <script src='https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2.0.1/dist/chartjs-plugin-zoom.umd.min.js'></script>
    
    <video id='bgvid' autoplay muted loop playsinline preload='auto' src='https://motionbgs.com/media/1046/emily-in-the-cyberpunk-city.960x540.mp4'></video>
    <div class='overlay'></div>
    
    <header><div class='inner'>
        <div class='brand'><div class='dot'></div><div style='color:#cbd5e1'>Overview</div></div>
        <div class='toolbar'>
            <a class='btn' href='?set".(!empty($config['panel_secret'])?"&secret=".rawurlencode($config['panel_secret']):"")."'>Settings</a>
            <a class='btn' href='?panel".(!empty($config['panel_secret'])?"&secret=".rawurlencode($config['panel_secret']):"")."&download=1'>Download Logs</a>
            <form method='post' style='display:inline'><button name='reset_logs' value='1' onclick='return confirm(\"Hapus semua log?\")'>Reset Logs</button></form>
        </div>
    </div></header>
    
    <div class='wrap'>";
    
    // KPI
    echo "<div class='cards'>
        <div class='card'>
            <div class='kpi-label'>Auto refresh</div>
            <div class='kpi-value'><span id='countdown'>60</span> <span class='muted'>seconds</span></div>
            <div style='height:8px'></div>
            <div class='kpi-label'>Views today</div>
            <div class='kpi-value'>".(int)$stats['views_today']." <span class='muted'>views</span></div>
        </div>
        <div class='card'>
            <div class='kpi-label'>Average views</div>
            <div class='kpi-value'>".(int)$stats['avg_per_day']." <span class='muted'>per day</span></div>
            <div style='height:8px'></div>
            <div class='kpi-label'>Views this month</div>
            <div class='kpi-value'>".(int)$stats['views_month']." <span class='muted'>views</span></div>
        </div>
        <div class='card'>
            <div class='kpi-label'>Human Today Count</div>
            <div class='kpi-value'>".(int)$stats['human_today']."</div>
            <div style='height:8px'></div>
            <div class='kpi-label'>Bot Today Count</div>
            <div class='kpi-value'>".(int)$stats['bot_today']."</div>
        </div>
    </div>";
    
    // BAR per-menit
    echo "<div class='panel'>
        <div class='panel-title'><span>Net Bar per Minute (Human − Bot)</span><span style='color:#cbd5e1'>Aggregated • newest on the right • updates every 1 min</span></div>
        <div class='chart'><canvas id='vchart'></canvas></div>
        <div class='slider-wrap'>
            <span class='muted'>Scroll</span>
            <input id='range' type='range' min='0' max='".(int)$max_slider."' step='1' value='".(int)$startIndex."' />
            <span class='muted'>".count($labels)." mins</span>
        </div>
    </div>";
    
    // Totals + Blocked IPs + Blocked ASNs
    echo "<div class='cards' style='margin-top:14px'>
        <div class='card'><div class='kpi-label'>Total visitors</div><div class='kpi-value'>".(int)$stats['total']."</div></div>
        <div class='card'><div class='kpi-label'>Total human</div><div class='kpi-value'>".(int)$stats['human']."</div></div>
        <div class='card'>
            <div class='kpi-label'>Total bot</div>
            <div class='kpi-value'>".(int)$stats['bot']."</div>
            <div class='blocked-ips-section'>
                <div class='kpi-label'>Custom Blocked IPs</div>
                <div class='kpi-value'>".count($blocked_ips)."</div>
                <div class='kpi-label'>Blocked ASNs</div>
                <div class='kpi-value'>".count($blocked_asns)."</div>
                <div class='blocked-ips-list'>
                    ".($blocked_asns ? 
                        implode('', array_map(function($asn) {
                            return "<div class='blocked-ip-item'><span>".h($asn)."</span></div>";
                        }, array_slice($blocked_asns, 0, 5)))
                        . (count($blocked_asns) > 5 ? "<div class='blocked-ip-item'><span>... and ".(count($blocked_asns)-5)." more</span></div>" : "")
                        : "<div style='color:var(--muted);text-align:center;padding:8px'>No blocked ASNs</div>"
                    )."
                </div>
            </div>
        </div>
    </div>";
    
    // Recent Humans (NEWEST FIRST + pagination 10)
    echo "<div class='panel'>
        <div class='panel-title'><span>Recent Humans</span>
        <span style='color:#cbd5e1'>Newest first • $humTotal rows • Page $humPage / $humPages</span>
        </div>
        <div class='toolbar' style='margin-top:8px;gap:8px'>
            <a class='btn' href='".$panelBase."&ph=".max(1, $humPage-1)."&pb=".$botPage."'>&larr; Prev</a>
            <a class='btn' href='".$panelBase."&ph=".min($humPages, $humPage+1)."&pb=".$botPage."'>Next &rarr;</a>
        </div>
        <div class='logs-wrap'><table>
            <thead><tr>
                <th style='width:64px'>#</th>
                <th style='width:150px'>Time (UTC)</th>
                <th style='width:130px'>IP</th>
                <th style='width:80px'>Country</th>
                <th>User-Agent</th>
                <th style='width:120px'>Verdict</th>
                <th style='width:240px'>ASN</th>
                <th style='width:120px'>Path</th>
            </tr></thead><tbody>";
    
    $ctr = $humStartIndex + 1; // penomoran global: #1 = paling baru
    foreach ($humSlice as $r) {
        $tag = "<span class='tag ok'>human</span>";
        $asnLine = trim(($r['asn'] ?? '').' • '.($r['as_name'] ?? ''));
        echo "<tr>
            <td>".($ctr++)."</td>
            <td>".h($r['time'] ?? '')."</td>
            <td>".h($r['ip'] ?? '')."</td>
            <td>".h($r['country_code'] ?? ($r['country'] ?? ''))."</td>
            <td style='word-break:break-all'>".h($r['ua'] ?? '')."</td>
            <td>$tag</td>
            <td style='word-break:break-word'>".h($asnLine)."</td>
            <td>".h($r['path'] ?? '')."</td>
        </tr>";
    }
    echo "</tbody></table></div>
        <div class='toolbar' style='margin-top:8px;gap:8px'>
            <a class='btn' href='".$panelBase."&ph=".max(1, $humPage-1)."&pb=".$botPage."'>&larr; Prev</a>
            <a class='btn' href='".$panelBase."&ph=".min($humPages, $humPage+1)."&pb=".$botPage."'>Next &rarr;</a>
        </div>
    </div>";
    
    // Recent Bots (NEWEST FIRST + pagination 10)
    echo "<div class='panel'>
        <div class='panel-title'><span>Recent Bots</span>
        <span style='color:#cbd5e1'>Newest first • $botTotal rows • Page $botPage / $botPages</span>
        </div>
        <div class='toolbar' style='margin-top:8px;gap:8px'>
            <a class='btn' href='".$panelBase."&pb=".max(1, $botPage-1)."&ph=".$humPage."'>&larr; Prev</a>
            <a class='btn' href='".$panelBase."&pb=".min($botPages, $botPage+1)."&ph=".$humPage."'>Next &rarr;</a>
        </div>
        <div class='logs-wrap'><table>
            <thead><tr>
                <th style='width:64px'>#</th>
                <th style='width:150px'>Time (UTC)</th>
                <th style='width:130px'>IP</th>
                <th style='width:80px'>Country</th>
                <th>User-Agent</th>
                <th style='width:120px'>Verdict</th>
                <th style='width:240px'>ASN</th>
                <th style='width:120px'>Path</th>
            </tr></thead><tbody>";
    
    $ctr2 = $botStartIndex + 1; // penomoran global: #1 = paling baru
    foreach ($botSlice as $r) {
        $tag = "<span class='tag bad'>bot</span>";
        $asnLine = trim(($r['asn'] ?? '').' • '.($r['as_name'] ?? ''));
        echo "<tr>
            <td>".($ctr2++)."</td>
            <td>".h($r['time'] ?? '')."</td>
            <td>".h($r['ip'] ?? '')."</td>
            <td>".h($r['country_code'] ?? ($r['country'] ?? ''))."</td>
            <td style='word-break:break-all'>".h($r['ua'] ?? '')."</td>
            <td>$tag</td>
            <td style='word-break:break-word'>".h($asnLine)."</td>
            <td>".h($r['path'] ?? '')."</td>
        </tr>";
    }
    echo "</tbody></table></div>
        <div class='toolbar' style='margin-top:8px;gap:8px'>
            <a class='btn' href='".$panelBase."&pb=".max(1, $botPage-1)."&ph=".$humPage."'>&larr; Prev</a>
            <a class='btn' href='".$panelBase."&pb=".min($botPages, $botPage+1)."&ph=".$humPage."'>Next &rarr;</a>
        </div>
    </div>";
    
    // ==== JS (BAR per-menit, refresh 60s) ====
    echo "</div>
    <script>
    const ALL_LABELS = $labels_js; // ['HH:MM', ...]
    const ALL_VALUES = $values_js; // [net, ...]
    let startIndex = ".(int)$startIndex.";
    const windowSize = 60; // tampil 60 menit (1 jam)
    const ctx = document.getElementById('vchart');
    const range = document.getElementById('range');
    
    function sliceWin(s, n){
        const e = Math.min(ALL_LABELS.length, s + n);
        return { labels: ALL_LABELS.slice(s, e), values: ALL_VALUES.slice(s, e) };
    }
    
    function barColors(values){
        const bg = [], br = [];
        for (let i = 0; i < values.length; i++) {
            const prev = (i === 0) ? values[i] : values[i-1];
            const up = values[i] >= prev;
            bg.push(up ? 'rgba(34,197,94,0.85)' : 'rgba(239,68,68,0.85)'); // green/red
            br.push(up ? 'rgb(34,197,94)' : 'rgb(239,68,68)');
        }
        return { bg, br };
    }
    
    const init = sliceWin(startIndex, windowSize);
    const cols = barColors(init.values);
    
    let chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: init.labels,
            datasets: [{
                label: 'Net per Minute (Human − Bot)',
                data: init.values,
                backgroundColor: cols.bg,
                borderColor: cols.br,
                borderWidth: 1,
                borderRadius: 5,
                maxBarThickness: 18,
                categoryPercentage: 0.9,
                barPercentage: 1.0
            }]
        },
        options: {
            maintainAspectRatio: false,
            animation: false,
            plugins: {
                legend: { labels: { color: '#e5e7eb' } },
                zoom: {
                    pan: { enabled: true, mode: 'x' },
                    zoom: {
                        wheel: { enabled: true },
                        pinch: { enabled: true },
                        mode: 'x'
                    }
                },
                tooltip: { intersect:false }
            },
            scales: {
                x: {
                    grid: { display:false },
                    ticks: { color:'#e5e7eb' }
                },
                y: {
                    grid: { color:'rgba(255,255,255,.15)' },
                    ticks: { color:'#e5e7eb', precision:0 },
                    beginAtZero: true
                }
            }
        }
    });
    
    if (range){
        range.addEventListener('input', (e) => {
            startIndex = parseInt(e.target.value || '0', 10);
            const win = sliceWin(startIndex, windowSize);
            const col = barColors(win.values);
            chart.data.labels = win.labels;
            chart.data.datasets[0].data = win.values;
            chart.data.datasets[0].backgroundColor = col.bg;
            chart.data.datasets[0].borderColor = col.br;
            chart.update();
        });
    }
    
    // Auto-refresh 60s + countdown
    let sec = 60;
    const el = document.getElementById('countdown');
    function tick(){
        if (sec <= 0) {
            location.reload();
            return;
        }
        if (el) el.textContent = String(sec);
        sec -= 1;
    }
    tick();
    setInterval(tick, 1000);
    </script>";
    exit;
}

// =============================
// Main traffic (log lalu redirect)
// =============================
$ip = client_ip();
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$path = $_SERVER['REQUEST_URI'] ?? '/';

// Step 0: Check Custom Blocked IPs
if (is_ip_blocked($ip, $blocked_ips)) {
    // Langsung redirect ke target_bot tanpa log tambahan
    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    header('Location: ' . $config['target_bot'], true, 302);
    exit;
}

// ✅ NEW: Step 1 - Check Blocked ASNs (untuk menghemat lisensi API)
$lite = ipinfo_lite($config['ipinfo_token'], $ip);
$client_asn = $lite['asn'] ?? '';

if ($client_asn && is_asn_blocked($client_asn, $blocked_asns)) {
    // ✅ NEW: Tambahkan IP ke blocked_ips.json untuk hemat API
    if (!in_array($ip, $blocked_ips)) {
        $blocked_ips[] = $ip;
        save_blocked_ips($BLOCKED_IPS_FILE, $blocked_ips);
    }
    // Redirect ke target_bot
    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    header('Location: ' . $config['target_bot'], true, 302);
    exit;
}

// Step 2: Heuristic UA
$uaLooksBot = is_bot_by_ua($ua);

// Step 3: NetDetective (verdict)
$nd = call_netdetective($config['rapidapi_key'], $ip, 5);
$cls = classify_from_api($nd);
if ($uaLooksBot) $cls['verdict'] = 'bot';

// Log row
$logRow = [
    'time' => gmdate('Y-m-d H:i:s'),
    'ip' => $ip,
    'country_code' => $lite['country_code'] ?? '',
    'country' => $lite['country'] ?? '',
    'ua' => $ua,
    'verdict' => $cls['verdict'] ?? 'human',
    'asn' => $lite['asn'] ?? '',
    'as_name' => $lite['as_name'] ?? '',
    'path' => $path,
];
log_visit($LOG_FILE, $logRow);

// Redirect
$target = ($cls['verdict'] === 'human') ? $config['target_human'] : $config['target_bot'];
if (empty($target)) $target = ($cls['verdict'] === 'human') ? 'https://example.com' : 'https://www.google.com';

header('Cache-Control: no-store');
header('Pragma: no-cache');
header('Location: '.$target, true, 302);
exit;