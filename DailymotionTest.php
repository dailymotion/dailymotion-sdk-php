<?php

$apiKey = null;
$apiSecret = null;
$testUser = null;
$testPassword = null;
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
    protected $api;

    protected function setUp()
    {
        global $apiKey, $apiSecret, $apiEndpointUrl, $oauthAuthorizeEndpointUrl, $oauthTokenEndpointUrl;
        $this->api = new Dailymotion($apiKey, $apiSecret);
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

    /**
     * @expectedException DailymotionAuthRequiredException
     */
    public function testNoGrantType()
    {
        $result = $this->api->call('test.echo', array('message' => 'test'));
    }

    public function testGrantTypeNone()
    {
        $this->api->setGrantType(Dailymotion::GRANT_TYPE_NONE);
        $result = $this->api->call('test.echo', array('message' => 'test'));
        $this->assertType('array', $result);
        $this->assertArrayHasKey('message', $result);
        $this->assertEquals('test', $result['message']);
    }

    public function testGrantTypePassword()
    {
        global $testUser, $testPassword;
        $this->api->setGrantType(Dailymotion::GRANT_TYPE_PASSWORD, array('username' => $testUser, 'password' => $testPassword));
        $result = $this->api->call('test.echo', array('message' => 'test'));
        $this->assertType('array', $result);
        $this->assertArrayHasKey('message', $result);
        $this->assertEquals('test', $result['message']);
    }

    public function testGrantTypeToken()
    {
    }

    /**
     * @expectedException DailymotionAuthRequiredException
     */
    public function testError()
    {
        $this->api->call('test.echo');
    }
}

