<?php

declare(strict_types=1);

namespace YakNet\YaCaptcha\Tests;

use PHPUnit\Framework\TestCase;
use YakNet\YaCaptcha\YaCaptcha;

class YaCaptchaTest extends TestCase
{
    public function testConstructorSetsProperties(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc', 'https://test.yakhub.com.tr/');
        
        $this->assertInstanceOf(YaCaptcha::class, $client);
    }

    public function testGetScriptTag(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc');
        $tag = $client->getScriptTag();
        
        $this->assertStringContainsString('<script type="module"', $tag);
        $this->assertStringContainsString('src="https://cdnjs.yakhub.com.tr/ajax/libs/yacaptcha/yacaptcha.js"', $tag);
        $this->assertStringContainsString('defer></script>', $tag);
    }

    public function testGetWidgetHtmlDefault(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc', 'https://developer-console.yakhub.com.tr');
        $html = $client->getWidgetHtml();

        $this->assertStringContainsString('<yacaptcha-widget', $html);
        $this->assertStringContainsString('challengeurl="https://developer-console.yakhub.com.tr/api/yacaptcha/challenge?client_id=client-123"', $html);
        $this->assertStringContainsString('auto="onload"', $html);
        $this->assertStringContainsString('hideogo="false"', $html);
        $this->assertStringContainsString('></yacaptcha-widget>', $html);
    }

    public function testGetWidgetHtmlCustom(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc', 'https://developer-console.yakhub.com.tr');
        $html = $client->getWidgetHtml('https://custom.com/challenge', [
            'auto' => 'onfocus',
            'custom-attr' => 'value1',
            'boolean-attr' => true
        ]);

        $this->assertStringContainsString('challengeurl="https://custom.com/challenge"', $html);
        $this->assertStringContainsString('auto="onfocus"', $html);
        $this->assertStringContainsString('custom-attr="value1"', $html);
        $this->assertStringContainsString('boolean-attr="true"', $html);
    }

    public function testGetWidgetHtmlWithMaxNumber(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc', 'https://developer-console.yakhub.com.tr');
        $html = $client->getWidgetHtml('', [
            'max_number' => 250000
        ]);

        $this->assertStringContainsString('challengeurl="https://developer-console.yakhub.com.tr/api/yacaptcha/challenge?client_id=client-123&amp;max_number=250000"', $html);
    }

    public function testVerifyReturnsFalseOnEmptyPayload(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc');
        $this->assertFalse($client->verify(''));
    }

    public function testVerifyWithMockSuccessResponse(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc');
        $client->setMockResponse(['success' => true]);

        $this->assertTrue($client->verify('valid-payload'));
    }

    public function testVerifyWithMockFailureResponse(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc');
        $client->setMockResponse(['success' => false]);

        $this->assertFalse($client->verify('invalid-payload'));
    }

    public function testInspectWafWithMockResponse(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc');
        $client->setMockResponse(['action' => 'challenge', 'threat_score' => 60]);

        $res = $client->inspectWaf();
        $this->assertEquals('challenge', $res['action']);
        $this->assertEquals(60, $res['threat_score']);
    }

    public function testRenderCloudflareChallengePage(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc');
        $html = $client->renderCloudflareChallengePage('Test Servis', '/target-url');

        $this->assertStringContainsString('<!DOCTYPE html>', $html);
        $this->assertStringContainsString('Güvenlik Kontrolü | Test Servis', $html);
        $this->assertStringContainsString('action="/target-url"', $html);
        $this->assertStringContainsString('<yacaptcha-widget', $html);
    }

    public function testAutoProtectAllowsCleanRequest(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc');
        $client->setMockResponse(['action' => 'allow', 'threat_score' => 0]);

        $res = $client->autoProtect('Test Servis');
        $this->assertEquals('allow', $res['action']);
    }

    public function testIsLegitimateSearchBotWithGooglebot(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc');
        $this->assertTrue($client->isLegitimateSearchBot('66.249.66.1', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'));
    }

    public function testIsLegitimateSearchBotWithSpoofedIp(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc');
        $this->assertFalse($client->isLegitimateSearchBot('1.1.1.1', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'));
    }

    public function testIsLegitimateSearchBotWithRegularUserAgent(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc');
        $this->assertFalse($client->isLegitimateSearchBot('66.249.66.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0'));
    }

    public function testAutoProtectAllowsLegitimateSearchBot(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc');
        $client->setMockResponse(['action' => 'challenge', 'threat_score' => 80]);

        $_SERVER['REMOTE_ADDR'] = '66.249.66.1';
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        $res = $client->autoProtect('Test Servis');
        $this->assertEquals('allow', $res['action']);
        $this->assertTrue($res['is_search_bot'] ?? false);
    }
}

