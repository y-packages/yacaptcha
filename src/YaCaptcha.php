<?php

declare(strict_types=1);

namespace YakNet\YaCaptcha;

class YaCaptcha
{
    private string $clientId;
    private string $clientSecret;
    private string $baseUrl;

    /**
     * @var array<string, mixed>|null Mock response for testing purposes
     */
    private ?array $mockResponse = null;

    public function __construct(string $clientId, string $clientSecret, string $baseUrl = 'https://auth.yakhub.com.tr')
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    /**
     * Captcha çözümünü YakNet Auth sunucusu üzerinden doğrular.
     *
     * @param string $payload Kullanıcı tarayıcısından gelen doğrulama verisi.
     * @return bool Doğrulama başarılı ise true, aksi halde false.
     */
    public function verify(string $payload): bool
    {
        if (empty($payload)) {
            return false;
        }

        // Testler için mock mekanizması
        if ($this->mockResponse !== null) {
            return isset($this->mockResponse['success']) && $this->mockResponse['success'] === true;
        }

        $url = $this->baseUrl . '/api/yacaptcha/verify';
        
        $postData = json_encode([
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'payload' => $payload,
        ]);

        if ($postData === false) {
            return false;
        }

        $ch = curl_init($url);
        if ($ch === false) {
            return false;
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $postData,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Accept: application/json',
            ],
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 12,
            CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        /** @var string|bool $response */
        $response = curl_exec($ch);
        /** @var int $httpCode */
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($response === false || $httpCode !== 200) {
            // SSL sertifika sorunu ihtimaline karşı yedek cURL denemesi
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        }

        curl_close($ch);

        if ($response === false || $httpCode !== 200) {
            return false;
        }

        /** @var array<string, mixed>|null $data */
        $data = json_decode((string) $response, true);
        
        if (!is_array($data)) {
            return false;
        }
        
        return isset($data['success']) && $data['success'] === true;
    }

    /**
     * Altcha widget'ını render etmek için gerekli olan HTML kodunu üretir.
     *
     * @param string $challengeUrl Opsiyonel özel challenge adresi. Boş bırakılırsa baseUrl üzerinden otomatik oluşturulur.
     * @param array<string, string|int|bool> $attributes Widget elementine eklenecek ek HTML öznitelikleri.
     * @param string $tagName Kullanılacak HTML etiket adı (Örn: yacaptcha-widget veya altcha-widget).
     * @return string HTML kodu.
     */
    public function getWidgetHtml(string $challengeUrl = '', array $attributes = [], string $tagName = 'yacaptcha-widget'): string
    {
        $maxNumber = null;
        if (isset($attributes['max_number'])) {
            $maxNumber = (int) $attributes['max_number'];
            unset($attributes['max_number']);
        }

        if (empty($challengeUrl)) {
            $challengeUrl = $this->baseUrl . '/api/yacaptcha/challenge?client_id=' . urlencode($this->clientId);
            if ($maxNumber !== null) {
                $challengeUrl .= '&max_number=' . $maxNumber;
            }
        }

        /** @var array<string, string|int|bool> $defaultAttributes */
        $defaultAttributes = [
            'challengeurl' => $challengeUrl,
            'auto' => 'onload',
            'hideogo' => 'false',
        ];

        $mergedAttributes = array_merge($defaultAttributes, $attributes);
        
        $htmlAttributes = [];
        foreach ($mergedAttributes as $key => $value) {
            $valStr = is_bool($value) ? ($value ? 'true' : 'false') : (string) $value;
            $htmlAttributes[] = htmlspecialchars($key) . '="' . htmlspecialchars($valStr) . '"';
        }

        $cleanTagName = htmlspecialchars($tagName);
        return '<' . $cleanTagName . ' ' . implode(' ', $htmlAttributes) . '></' . $cleanTagName . '>';
    }

    /**
     * Altcha widget'ı için gerekli olan JavaScript dosyasını döndüren script etiketini üretir.
     *
     * @param string $cdnUrl JavaScript dosyasının adresi.
     * @return string `<script>` etiketi.
     */
    public function getScriptTag(string $cdnUrl = 'https://auth.yakhub.com.tr/js/yacaptcha.js'): string
    {
        return '<script type="module" src="' . htmlspecialchars($cdnUrl) . '" defer></script>';
    }

    /**
     * WAF isteğini YakNet Auth WAF servisi üzerinden denetler.
     *
     * @param array<string, mixed> $customParams Opsiyonel özel denetim parametreleri.
     * @return array<string, mixed> WAF denetim sonucu (action, threat_score, detected_threats vb.)
     */
    public function inspectWaf(array $customParams = []): array
    {
        if ($this->mockResponse !== null) {
            return $this->mockResponse;
        }

        $url = $this->baseUrl . '/api/yacaptcha/waf-check';

        $rawIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $ip = is_string($rawIp) ? $rawIp : '0.0.0.0';
        if (str_contains($ip, ',')) {
            $ip = trim(explode(',', $ip)[0]);
        }

        $userAgent = is_string($_SERVER['HTTP_USER_AGENT'] ?? null) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $uri = is_string($_SERVER['REQUEST_URI'] ?? null) ? $_SERVER['REQUEST_URI'] : '';
        $method = is_string($_SERVER['REQUEST_METHOD'] ?? null) ? $_SERVER['REQUEST_METHOD'] : 'GET';

        $params = array_merge([
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'ip'            => $ip,
            'user_agent'    => $userAgent,
            'uri'           => $uri,
            'method'        => $method,
            'params'        => array_merge($_GET, $_POST),
        ], $customParams);

        $postData = json_encode($params);
        if ($postData === false) {
            return ['action' => 'allow', 'threat_score' => 0, 'detected_threats' => []];
        }

        $ch = curl_init($url);
        if ($ch === false) {
            return ['action' => 'allow', 'threat_score' => 0, 'detected_threats' => []];
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $postData,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Accept: application/json',
            ],
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
        ]);

        /** @var string|bool $response */
        $response = curl_exec($ch);
        curl_close($ch);

        if (!is_string($response)) {
            return ['action' => 'allow', 'threat_score' => 0, 'detected_threats' => []];
        }

        /** @var array<string, mixed>|null $data */
        $data = json_decode($response, true);
        if (!is_array($data)) {
            return ['action' => 'allow', 'threat_score' => 0, 'detected_threats' => []];
        }

        return $data;
    }

    /**
     * WAF denetimini gerçekleştirir ve Cloud Console ayarlarınıza göre (Engelleme / Challenge) işlemleri OTOMATİK uygular.
     * Developer uygulamasında tek satır çağrılması yeterlidir ($yaCaptcha->autoProtect()).
     *
     * @param string $siteName Korunan Hedef Site/Servis başlığı (Örn: Yamail Webmail)
     * @param array<string, mixed> $customParams Opsiyonel özel denetim parametreleri.
     * @return array<string, mixed> WAF sonucu (istek başarılı ise)
     */
    public function autoProtect(string $siteName = 'Korunan Web Sitesi', array $customParams = []): array
    {
        $rawIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $ip = is_string($rawIp) ? $rawIp : '0.0.0.0';
        if (str_contains($ip, ',')) {
            $ip = trim(explode(',', $ip)[0]);
        }
        $clearanceToken = md5($this->clientId . '_' . $ip);

        // Check AJAX WAF Verification request from Challenge Page
        $isWafVerify = (isset($_SERVER['HTTP_X_YAK_WAF_VERIFY']) && $_SERVER['HTTP_X_YAK_WAF_VERIFY'] === '1') 
            || (isset($_POST['yak_waf_verify']) && $_POST['yak_waf_verify'] === '1');

        if ($isWafVerify) {
            $rawPayload = $_POST['yak_captcha_payload'] ?? $_POST['altcha'] ?? '';
            $payload = is_string($rawPayload) ? $rawPayload : '';

            $isValid = ($payload !== '' && $this->verify($payload));
            if ($isValid) {
                if (!headers_sent()) {
                    setcookie('yak_waf_clearance', $clearanceToken, time() + 7200, '/');
                    header('Content-Type: application/json; charset=utf-8');
                }
                echo json_encode(['success' => true]);
                exit;
            } else {
                if (!headers_sent()) {
                    header('Content-Type: application/json; charset=utf-8', true, 400);
                }
                echo json_encode(['success' => false, 'error' => 'Invalid captcha payload']);
                exit;
            }
        }

        if (isset($_COOKIE['yak_waf_clearance']) && $_COOKIE['yak_waf_clearance'] === $clearanceToken) {
            $customParams['is_cleared'] = true;
        }

        $wafResult = $this->inspectWaf($customParams);

        if (isset($wafResult['action']) && $wafResult['action'] === 'block') {
            if (!headers_sent()) {
                header('HTTP/1.1 403 Forbidden');
                header('Content-Type: text/html; charset=utf-8');
            }
            echo '<!DOCTYPE html><html lang="tr"><head><meta charset="UTF-8"><title>403 Forbidden | YakNet WAF</title><style>body{font-family:sans-serif;background:#0b0f19;color:#f87171;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}.card{background:#111827;border:1px solid rgba(255,255,255,0.1);padding:40px;border-radius:16px;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,0.5);}h1{margin-top:0;}p{color:#9ca3af;}</style></head><body><div class="card"><h1>403 - Erişim Engellendi</h1><p>Şüpheli güvenlik ihlali tespit edildi. İsteğiniz YakNet WAF tarafından engellendi.</p></div></body></html>';
            exit;
        }

        if (isset($wafResult['action']) && $wafResult['action'] === 'challenge') {
            $rawPayload = $_POST['yak_captcha_payload'] ?? $_POST['altcha'] ?? null;
            $payload = is_string($rawPayload) ? $rawPayload : '';

            if ($payload !== '' && $this->verify($payload)) {
                if (!headers_sent()) {
                    setcookie('yak_waf_clearance', $clearanceToken, time() + 7200, '/');
                }
                $_COOKIE['yak_waf_clearance'] = $clearanceToken;
                return $wafResult;
            }

            if (!headers_sent()) {
                header('Content-Type: text/html; charset=utf-8');
            }
            
            // Prefer centrally rendered official HTML from auth.yakhub.com.tr
            if (isset($wafResult['challenge_html']) && is_string($wafResult['challenge_html']) && $wafResult['challenge_html'] !== '') {
                echo $wafResult['challenge_html'];
            } else {
                echo $this->renderCloudflareChallengePage($siteName);
            }
            exit;
        }

        return $wafResult;
    }

    /**
     * Cloudflare Turnstile tarzı tam sayfa Güvenlik Kontrolü (Challenge) HTML şablonunu üretir.
     * Brand bilgileri (YakNet WAF & yaCAPTCHA) sabittir ve değiştirilemez.
     *
     * @param string $siteName Korunan Hedef Site/Servis başlığı (Örn: Yamail Webmail)
     * @param string $targetUrl Başarılı doğrulama sonrası yönlendirilecek hedef adres
     * @return string Full-page HTML
     */
    public function renderCloudflareChallengePage(string $siteName = 'Korunan Web Sitesi', string $targetUrl = ''): string
    {
        if (empty($targetUrl)) {
            $rawUri = $_SERVER['REQUEST_URI'] ?? '/';
            $targetUrl = is_string($rawUri) ? $rawUri : '/';
        }

        $rayId = strtoupper(bin2hex(random_bytes(8)));
        $rawIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $clientIp = htmlspecialchars(is_string($rawIp) ? $rawIp : '0.0.0.0');
        $cleanSiteName = htmlspecialchars($siteName);
        $cleanTargetUrl = htmlspecialchars($targetUrl);

        $widgetHtml = $this->getWidgetHtml('', ['auto' => 'onload', 'name' => 'yak_captcha_payload']);
        $scriptTag = $this->getScriptTag();

        return <<<HTML
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Güvenlik Kontrolü | {$cleanSiteName}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    {$scriptTag}
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: #0b0f19;
            color: #f3f4f6;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 24px;
            overflow-x: hidden;
            position: relative;
        }
        body::before {
            content: '';
            position: absolute;
            top: -150px;
            left: 50%;
            transform: translateX(-50%);
            width: 600px;
            height: 600px;
            background: radial-gradient(circle, rgba(168, 85, 247, 0.15) 0%, rgba(11, 15, 25, 0) 70%);
            pointer-events: none;
        }
        .challenge-card {
            width: 100%;
            max-width: 480px;
            background: rgba(17, 24, 39, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 20px;
            padding: 36px 32px;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            text-align: center;
            position: relative;
            z-index: 10;
        }
        .brand-header {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            margin-bottom: 24px;
        }
        .brand-icon-shield {
            width: 42px;
            height: 42px;
            background: linear-gradient(135deg, #9333ea 0%, #a855f7 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 20px rgba(168, 85, 247, 0.4);
        }
        .brand-icon-shield svg {
            width: 22px;
            height: 22px;
            stroke: #fff;
            fill: none;
            stroke-width: 2.2;
        }
        .brand-title {
            font-size: 20px;
            font-weight: 700;
            color: #ffffff;
            letter-spacing: -0.5px;
        }
        .challenge-title {
            font-size: 17px;
            font-weight: 600;
            color: #e5e7eb;
            margin-bottom: 8px;
        }
        .challenge-subtitle {
            font-size: 13.5px;
            color: #9ca3af;
            line-height: 1.5;
            margin-bottom: 28px;
        }
        .widget-wrapper {
            margin-bottom: 28px;
            text-align: left;
        }
        .footer-info {
            font-size: 11.5px;
            color: #6b7280;
            border-top: 1px solid rgba(255, 255, 255, 0.06);
            padding-top: 20px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .footer-info span { color: #9ca3af; font-family: monospace; }
        .footer-brand { color: #a855f7; text-decoration: none; font-weight: 700; }
        .footer-brand:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="challenge-card">
        <div class="brand-header">
            <div class="brand-icon-shield">
                <svg viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
            </div>
            <div class="brand-title">YakNet WAF</div>
        </div>

        <h1 class="challenge-title">Güvenlik Kontrolü Yapılıyor</h1>
        <p class="challenge-subtitle">{$cleanSiteName} adresine erişmeden önce bağlantı güvenliğiniz ve tarayıcınız YakNet WAF tarafından doğrulanıyor. Lütfen bekleyin...</p>

        <form id="challenge-form" method="POST" action="{$cleanTargetUrl}">
            <div class="widget-wrapper">
                {$widgetHtml}
            </div>
        </form>

        <div class="footer-info">
            <div>İstemci IP: <span>{$clientIp}</span></div>
            <div>Ray ID: <span>{$rayId}</span></div>
            <div style="margin-top: 4px;">Protected by <a href="https://yakhub.com.tr" target="_blank" class="footer-brand">YakNet WAF & yaCAPTCHA</a></div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const widget = document.querySelector('yacaptcha-widget');
            if (widget) {
                widget.addEventListener('statechange', function(e) {
                    if (e.detail && e.detail.state === 'verified' && e.detail.payload) {
                        fetch(window.location.href, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'X-Yak-Waf-Verify': '1'
                            },
                            body: 'yak_captcha_payload=' + encodeURIComponent(e.detail.payload) + '&yak_waf_verify=1'
                        })
                        .then(function(res) { return res.json(); })
                        .then(function(data) {
                            if (data && data.success) {
                                window.location.reload();
                            } else {
                                const form = document.getElementById('challenge-form');
                                if (form) { form.submit(); }
                            }
                        })
                        .catch(function() {
                            const form = document.getElementById('challenge-form');
                            if (form) { form.submit(); }
                        });
                    }
                });
            }
        });
    </script>
</body>
</html>
HTML;
    }

    /**
     * Testler için mock yanıtı ayarlar.
     *
     * @param array<string, mixed> $response
     * @return void
     */
    public function setMockResponse(array $response): void
    {
        $this->mockResponse = $response;
    }
}
