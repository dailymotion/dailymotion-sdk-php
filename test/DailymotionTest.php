<?php

use baorv\dailymotion\Dailymotion;
use baorv\dailymotion\exceptions\DailymotionApiException;
use baorv\dailymotion\exceptions\DailymotionAuthRequiredException;
use PHPUnit\Framework\TestCase;

class DailymotionTest extends TestCase
{
    protected $api = null;
    protected $apiKey = null;
    protected $apiSecret = null;

    public function testNoGrantTypePublicData()
    {
        $message = 'test';
        $result = $this->api->get('/echo', [
            'message' => $message
        ]);

        $this->assertInternalType('array', $result);
        $this->assertArrayHasKey('message', $result);
        $this->assertContains($message, $result);
    }

    /**
     * @expectedException DailymotionApiException
     */
    public function testError()
    {
        $this->api->get('/echo');
    }

    /**
     * @expectedException DailymotionAuthRequiredException
     */
    public function testNoGrantTypeAuthRequired()
    {
        $this->api->get('/videos/subscriptions');
    }

    /**
     * @expectedException DailymotionApiException
     */
    public function testNoGrantTypeAuthRequiredMe()
    {
        $this->api->get('/me');
    }

    public function testGrantTypeClientCredentials()
    {
        $this->api->setGrantType(
            Dailymotion::GRANT_TYPE_CLIENT_CREDENTIALS,
            $this->apiKey, $this->apiSecret
        );
        $result = $this->api->get('/auth');
        $this->assertInternalType('array', $result);
        $this->assertArrayHasKey('username', $result);
    }

    public function testGrantTypePassword()
    {
        global $testUser,
               $testPassword;

        $this->api->setGrantType(
            Dailymotion::GRANT_TYPE_PASSWORD,
            $this->apiKey, $this->apiSecret, array(),
            array('username' => $testUser, 'password' => $testPassword)
        );
        $result = $this->api->get('/auth');

        $this->assertInternalType('array', $result);
        $this->assertArrayHasKey('username', $result);
        $this->assertEquals($result['username'], $testUser);
    }

    /**
     * @expectedException DailymotionAuthRequiredException
     */
    public function testGrantTypeChangeFromSessionRequired()
    {
        try {
            $this->api->setGrantType(
                Dailymotion::GRANT_TYPE_CLIENT_CREDENTIALS,
                $this->apiKey, $this->apiSecret
            );
            $result = $this->api->get('/auth');
            $this->assertInternalType('array', $result);
        } catch (DailymotionAuthRequiredException $e) {
            // Test must not succeed if this call throws the exception
        }
        $this->api->setGrantType(
            Dailymotion::GRANT_TYPE_PASSWORD,
            $this->apiKey, $this->apiSecret
        );
        $this->api->get('/auth'); // should throw auth required exception
    }

    public function testVideoUpload()
    {
        global $testUser,
               $testPassword,
               $testVideoFile;

        $this->api->setGrantType(
            Dailymotion::GRANT_TYPE_PASSWORD,
            $this->apiKey,
            $this->apiSecret,
            array('read', 'write', 'delete', 'manage_videos'),
            array('username' => $testUser, 'password' => $testPassword)
        );
        $url = $this->api->uploadFile($testVideoFile);
        $this->assertInternalType('string', $url);
        $this->assertContains('http://', $url);

        $result = $this->api->post('/me/videos', array('url' => $url));
        $this->assertArrayHasKey('id', $result);

        sleep(2);
        $result = $this->api->delete("/video/{$result['id']}");
        $this->assertInternalType('array', $result);
    }

    protected function setUp()
    {
        global $apiKey,
               $apiSecret,
               $proxy,
               $apiEndpointUrl,
               $oauthAuthorizeEndpointUrl,
               $oauthTokenEndpointUrl;

        $this->api = new Dailymotion();
        $this->apiKey = $apiKey;
        $this->apiSecret = $apiSecret;

        if (!empty($proxy)) {
            $this->api->proxy = $proxy;
        }
        if (!empty($apiEndpointUrl)) {
            $this->api->apiEndpointUrl = $apiEndpointUrl;
        }
        if (!empty($oauthAuthorizeEndpointUrl)) {
            $this->api->oauthAuthorizeEndpointUrl = $oauthAuthorizeEndpointUrl;
        }
        if (!empty($oauthTokenEndpointUrl)) {
            $this->api->oauthTokenEndpointUrl = $oauthTokenEndpointUrl;
        }
    }
}