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
        $result = $this->api->call('auth.info');
    }

    public function testGrantTypeNone()
    {
        $this->api->setGrantType(Dailymotion::GRANT_TYPE_NONE, $this->apiKey, $this->apiSecret);
        $result = $this->api->call('auth.info');
        $this->assertType('array', $result);
        $this->assertArrayHasKey('username', $result);
    }

    public function testGrantTypePassword()
    {
        global $testUser, $testPassword;
        $this->api->setGrantType(Dailymotion::GRANT_TYPE_PASSWORD, $this->apiKey, $this->apiSecret, null, array('username' => $testUser, 'password' => $testPassword));
        $result = $this->api->call('auth.info');
        $this->assertType('array', $result);
        $this->assertArrayHasKey('username', $result);
    }

    public function testGrantTypeToken()
    {
    }

    /**
     * @expectedException DailymotionApiException
     */
    public function testError()
    {
        $this->api->call('test.echo');
    }

    public function testUploadFile()
    {
        global $testVideoFile;
        $this->api->setGrantType(Dailymotion::GRANT_TYPE_NONE, $this->apiKey, $this->apiSecret);
        $url = $this->api->uploadFile($testVideoFile);
        $this->assertType('string', $url);
        $this->assertContains('http://', $url);
    }
}

