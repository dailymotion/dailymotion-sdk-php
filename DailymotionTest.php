<?php

$apiKey = null;
$apiSecret = null;
$testUser = null;
$testPassword = null;
$testVideoFile = null;
$proxy = null;
$apiEndpointUrl = null;
$oauthAuthorizeEndpointUrl = null;
$oauthTokenEndpointUrl = null;

@include 'local_config.php';

if (!function_exists('readline'))
{
    function readline($prompt = '')
    {
        echo $prompt;
        return rtrim(fgets(STDIN), "\n");
    }
}

if (!$apiKey) $apiKey = readline('API Key: ');
if (!$apiSecret) $apiSecret = readline('API Secret: ');
if (!$testUser) $testUser = readline('Test User: ');
if (!$testPassword) $testPassword = readline('Test User Password: ');

require_once 'Dailymotion.php';

class DailymotionTest extends PHPUnit_Framework_TestCase
{
    protected
        $api = null,
        $apiKey = null,
        $apiSecret = null;

    protected function setUp()
    {
        global $apiKey, $apiSecret, $proxy, $apiEndpointUrl, $oauthAuthorizeEndpointUrl, $oauthTokenEndpointUrl;
        $this->apiKey = $apiKey;
        $this->apiSecret = $apiSecret;
        $this->api = new Dailymotion();
        if (isset($proxy))
        {
            $this->api->proxy = $proxy;
        }
        if (isset($apiEndpointUrl))
        {
            $this->api->apiEndpointUrl = $apiEndpointUrl;
        }
        if (isset($oauthAuthorizeEndpointUrl))
        {
            $this->api->oauthAuthorizeEndpointUrl = $oauthAuthorizeEndpointUrl;
        }
        if (isset($oauthTokenEndpointUrl))
        {
            $this->api->oauthTokenEndpointUrl = $oauthTokenEndpointUrl;
        }
    }

    public function testNoGrantTypePublicData()
    {
        $result = $this->api->call('test.echo', array('message' => 'test'));
    }

    /**
     * @expectedException DailymotionAuthRequiredException
     */
    public function testNoGrantTypeAuthRequired()
    {
        $result = $this->api->call('video.subscriptions');
    }

    public function testGrantTypeClientCredentials()
    {
        $this->api->setGrantType(Dailymotion::GRANT_TYPE_CLIENT_CREDENTIALS, $this->apiKey, $this->apiSecret);
        $result = $this->api->call('auth.info');
        $this->assertInternalType('array', $result);
        $this->assertArrayHasKey('username', $result);
    }

    public function testGrantTypePassword()
    {
        global $testUser, $testPassword;
        $this->api->setGrantType(Dailymotion::GRANT_TYPE_PASSWORD, $this->apiKey, $this->apiSecret, null, array('username' => $testUser, 'password' => $testPassword));
        $result = $this->api->call('auth.info');
        $this->assertInternalType('array', $result);
        $this->assertArrayHasKey('username', $result);

        $this->api->setGrantType(Dailymotion::GRANT_TYPE_PASSWORD, $this->apiKey, $this->apiSecret);
        $result = $this->api->call('auth.info');
        $this->assertInternalType('array', $result);
        $this->assertArrayHasKey('username', $result);
        $this->assertEquals($result['username'], $testUser);
    }

    public function testGrantTypeToken()
    {
    }

    /**
     * @expectedException DailymotionAuthRequiredException
     */
    public function testGrantTypeChangeFromSessionRequired()
    {
        global $testUser, $testPassword;
        try
        {
            $this->api->setGrantType(Dailymotion::GRANT_TYPE_CLIENT_CREDENTIALS, $this->apiKey, $this->apiSecret);
            $result = $this->api->call('auth.info');
            $this->assertInternalType('array', $result);
        }
        catch (DailymotionAuthRequiredException $e)
        {
            // Test must not succeed if this call throws the exception
        }

        $this->api->setGrantType(Dailymotion::GRANT_TYPE_PASSWORD, $this->apiKey, $this->apiSecret);
        $this->api->call('auth.info'); // should throw auth required exception
    }

    /**
     * @expectedException DailymotionApiException
     */
    public function testError()
    {
        $this->api->call('test.echo');
    }

    public function testVideoUpload()
    {
        global $testUser, $testPassword, $testVideoFile;
        $this->api->setGrantType(Dailymotion::GRANT_TYPE_PASSWORD, $this->apiKey, $this->apiSecret, array('write','delete'), array('username' => $testUser, 'password' => $testPassword));
        $url = $this->api->uploadFile($testVideoFile);
        $this->assertInternalType('string', $url);
        $this->assertContains('http://', $url);
        $result = $this->api->call('video.create', array('url' => $url));
        $this->assertArrayHasKey('id', $result);
        $this->api->call('video.delete', array('id' => $result['id']));
    }
}

