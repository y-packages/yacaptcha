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

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Accept: application/json',
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        /** @var string|bool $response */
        $response = curl_exec($ch);
        /** @var int $httpCode */
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
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
     * @return string `<altcha-widget>` HTML kodu.
     */
    public function getWidgetHtml(string $challengeUrl = '', array $attributes = []): string
    {
        if (empty($challengeUrl)) {
            $challengeUrl = $this->baseUrl . '/api/yacaptcha/challenge?client_id=' . urlencode($this->clientId);
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

        return '<altcha-widget ' . implode(' ', $htmlAttributes) . '></altcha-widget>';
    }

    /**
     * Altcha widget'ı için gerekli olan JavaScript dosyasını (CDN) döndüren script etiketini üretir.
     *
     * @param string $cdnUrl Altcha JavaScript dosyasının CDN adresi.
     * @return string `<script>` etiketi.
     */
    public function getScriptTag(string $cdnUrl = 'https://cdnjs.yakhub.com.tr/altcha/altcha.min.js'): string
    {
        return '<script type="module" src="' . htmlspecialchars($cdnUrl) . '" defer></script>';
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
