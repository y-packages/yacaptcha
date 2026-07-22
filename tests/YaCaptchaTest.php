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
        $this->assertStringContainsString('src="https://auth.yakhub.com.tr/js/yacaptcha.js"', $tag);
        $this->assertStringContainsString('defer></script>', $tag);
    }

    public function testGetWidgetHtmlDefault(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc', 'https://auth.yakhub.com.tr');
        $html = $client->getWidgetHtml();

        $this->assertStringContainsString('<yacaptcha-widget', $html);
        $this->assertStringContainsString('challengeurl="https://auth.yakhub.com.tr/api/yacaptcha/challenge?client_id=client-123"', $html);
        $this->assertStringContainsString('auto="onload"', $html);
        $this->assertStringContainsString('hideogo="false"', $html);
        $this->assertStringContainsString('></yacaptcha-widget>', $html);
    }

    public function testGetWidgetHtmlCustom(): void
    {
        $client = new YaCaptcha('client-123', 'secret-abc', 'https://auth.yakhub.com.tr');
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
        $client = new YaCaptcha('client-123', 'secret-abc', 'https://auth.yakhub.com.tr');
        $html = $client->getWidgetHtml('', [
            'max_number' => 250000
        ]);

        $this->assertStringContainsString('challengeurl="https://auth.yakhub.com.tr/api/yacaptcha/challenge?client_id=client-123&amp;max_number=250000"', $html);
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
}
