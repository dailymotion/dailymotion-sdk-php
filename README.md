Dailymotion PHP SDK
===================

This repository contains the official open source PHP SDK that facilitates access to the [**Dailymotion Graph API**](http://developer.dailymotion.com/documentation/#graph-api) from your PHP application. For more information about developing with Dailymotion's services, head to the [Developer Area](http://developer.dailymotion.com).

Usage
-----

**The PHP SDK implements the Dailymotion [Advanced API](http://developer.dailymotion.com/documentation/#advanced-api).** For a list of all available methods, see the complete [API reference](http://developer.dailymotion.com/documentation/#api-reference). To call a method using the PHP SDK, use the `get`, `post` or `delete` methods as follow:

```php
$api = new Dailymotion();
$result = $api->get(
    '/videos',
    array('fields' => array('id', 'title', 'owner'))
);
```

The `$result` variable contains the result of the method (as described in the [Graph API overview](http://developer.dailymotion.com/documentation/#response-types)) as an [`array`](http://developer.dailymotion.com/documentation/#type-array).

#### Authentication

The Dailymotion API requires OAuth 2.0 authentication in order to access protected resources.

Contrary to most OAuth SDKs, the Dailymotion PHP SDK implements **lazy authentication**, which means that no authentication request is sent as long as no data is requested from the API. At which point, two requests are sent back-to-back during the first request for information, one to authenticate and one to fetch the data. Keep this in mind while working through the rest of the documentation.

Please note that **the Dailymotion PHP SDK also takes care of abstracting the entire OAuth flow**, from retrieving, storing and using access tokens, to using refresh tokens to gather new access tokens automatically. You shouldn't have to deal with access tokens manually but if you have to, at the programming-level, the SDK exposes this information with the `Dailymotion::getSession()` and `Dailymotion::setSession()` methods. At the OAuth-level, a _session_ is the response sent by the OAuth server when successfully authenticated, for example:

```js
{
    "access_token": "<ACCESS_TOKEN>",
    "token_type": "Bearer",
    "expires_in": 36000,
    "refresh_token": "<REFRESH_TOKEN>",
    "scope": "<SCOPE1 SCOPE2 SCOPE3>",
    "uid": "<USER_ID>"
}
```

**Note:** One of the problems with OAuth 2.0 is that the specification doesn't offer any mechanism to upgrade the scope of an existing session. To add new scopes to an already existing session, you first need to call the `Dailymotion::logout()` method and start a new session with your new list of scopes.

If you really wish to manually retrieve an access token without waiting for the SDK to take care of it when sending the first query, you can use the  `Dailymotion::getAccessToken()` method. It will try to authenticate and return you the corresponding access token or an exception. Please note that this isn't the recommended way to proceed. See the [Overloading the SDK](#overloading-the-sdk) section for more information about handling access tokens.

This library implements three OAuth 2.0 granting methods for different kind of usages.

##### Authorization Grant Type

This grant type is the one you should use in most cases. With this grant type you redirect the user to an authorization page on Dailymotion and your application is called back once the end-user authorized your API key to access Dailymotion on his/her behalf.

Here is a usage example:

```php
// Instanciate the PHP SDK.
$api = new Dailymotion();

// Tell the SDK what kind of authentication you'd like to use.
// Because the SDK works with lazy authentication, no request is performed at this point.
$api->setGrantType(Dailymotion::GRANT_TYPE_AUTHORIZATION, $apiKey, $apiSecret);

try
{
    // The following line will actually try to authenticate before making the API call.
    // * The SDK takes care of retrying if the access token has expired.
    // * The SDK takes care of storing the access token itself using its `readSession()`
    //   and `storeSession()` methods that are made to be overridden in an extension
    //   of the class if you want a different storage than provided by default.
    $result = $api->get(
        '/me/videos',
        array('fields' => array('id', 'title', 'owner'))
    );
}
catch (DailymotionAuthRequiredException $e)
{
    // If the SDK doesn't have any access token stored in memory, it tries to
    // redirect the user to the Dailymotion authorization page for authentication.
    return header('Location: ' . $api->getAuthorizationUrl());
}
catch (DailymotionAuthRefusedException $e)
{
    // Handle the situation when the user refused to authorize and came back here.
    // <YOUR CODE>
}
```

##### Password Grant Type

If your PHP application isn't a web application and cannot redirect the user to the Dailymotion authorization page, the password grant type can be used instead of the authorization one. With this grant type you have the responsibility to ask the user for its credentials. **Make sure your API secret remains secret though**, do not use this kind of authentication for any service that is running on the client if you do not want your API secret to be publicly exposed.

Here is a usage example:

```php
// Instanciate the PHP SDK.
$api = new Dailymotion();

// Ask the end-user for his/her Dailymotion credentials in a way or another.
if (empty($_POST['username']) || empty($_POST['password']))
{
    // <YOUR CODE>
}
else
{
    // Tell the SDK what kind of authentication you'd like to use. Because the SDK
    // works with lazy authentication, no request is performed at this point.
    $api->setGrantType(
        Dailymotion::GRANT_TYPE_PASSWORD, 
        $apiKey,
        $apiSecret,
        array(), // OAuth 2.0 scopes that you'd like to be granted by the end-user
        array(
            'username' => $_POST['username'], // don't forget to sanitize this,
            'password' => $_POST['password'], // never use POST variables this way
        )
    );
    // The following line will actually try to authenticate before making the API call.
    // * The SDK takes care of retrying if the access token has expired.
    // * The SDK takes care of storing the access token itself using its `readSession()`
    //   and `storeSession()` methods that are made to be overridden in an extension
    //   of the class if you want a different storage than provided by default.
    $result = $api->get(
        '/me/videos',
        array('fields' => array('id', 'title', 'owner'))
    );
}
```

##### Client Credentials Grant Type

If you don't need to access the Dailymotion API on behalf of someone else because, for instance, you only plan to access public data, you can use the client credentials grant type. With this grant type, you will only have access to public data or data protected by a specific scope and/or role. It's the equivalent of being unlogged but having the permission (granted by Dailymotion as part of a partners program or similar) to access sensitive data.

Here is a usage example:

```php
// Instanciate the PHP SDK.
$api = new Dailymotion();

// Tell the SDK what kind of authentication you'd like to use. 
// Because the SDK works with lazy authentication, no request is performed at this point.
$api->setGrantType(Dailymotion::GRANT_TYPE_CLIENT_CREDENTIALS, $apiKey, $apiSecret);

// This will actually try to authenticate before making the API call.
// * The SDK takes care of retrying if the access token has expired.
// * The SDK takes care of storing the access token itself using its `readSession()`
//   and `storeSession()` methods that are made to be overridden in an extension
//   of the class if you want a different storage than provided by default.
$result = $api->get(
    '/videos',
    array('fields' => array('id', 'title', 'owner'))
);
```

There is no authenticated user in this scenario, thus you won't be able to access the `/me` endpoint.

#### Upload File

Some methods like `POST /me/videos` requires a URL to a file.
To create those URLs, Dailymotion offers a temporary upload service through the `Dailymotion::uploadFile()` method which can be used like this:

```php
// Temporarily upload a file on Dailymotion' servers
// This does not create a video, it only offers you a public URL to work with.
$url = $api->uploadFile($filePath);
var_dump($url);
```

You can then use this `$url` result as an argument to methods requiring such a parameter.
For instance to create a video:

```php
// More fields may be mandatory in order to create a video.
// Please refer to the complete API reference for a list of all the required data.
$result = $api->post(
    '/me/videos',
    array('url' => $url, 'title' => $videoTitle)
);
```
You can also retrieve a progress URL like this:

```php
$progressUrl = null;
$url = $api->uploadFile($filePath, null, $progressUrl);
var_dump($progressUrl);
```

Hitting this URL after the upload has started allows you to monitor the upload progress.

#### Overloading the SDK

As stated in the [Authentication section](#authentication) above, the PHP SDK takes care of abstracting the entire OAuth flow, from retrieving, storing and using access tokens, to using refresh tokens to gather new access tokens automatically. 

Overloading the SDK with your own implementation allows you to adapt the SDK behaviour to your needs. The most common usage is to overload both `Dailymotion::storeSession()` and `Dailymotion::readSession()` methods to change the default storage system (which uses cookies).

Here is a crude example of overloading the SDK to store sessions (access token + refresh token) on the file system instead of using cookies (for a command line program for example):

```php
class DailymotionCli extends Dailymotion
{
    /**
     * Where to store the current application session.
     * @var string
     */
    protected static $sessionFile;

    /**
     * Define where to store the session on the file system.
     */
    public function __construct()
    {
        self::$sessionFile = __DIR__ . '/api-session.json';
    }
    /**
     * Overloading the default implementation with file system implementation.
     * `readSession` is used to restore the session from its storage medium.
     * @return array Restored session information.
     */
    protected function readSession()
    {
        $session = json_decode(file_get_contents(self::$sessionFile), true);
        return $session;
    }
    /**
     * Overloading the default implementation with file system implementation.
     * `storeSession` is used to store the session to its storage medium.
     *
     * @param array $session Session information to store.
     * @return DailymotionCli $this
     */
    protected function storeSession(array $session = array())
    {
        file_put_contents(self::$sessionFile, json_encode($session), LOCK_EX);
        return $this;
    }
}
```

Don't hesitate to extend the functionalities of the SDK and send us [pull requests](https://github.com/dailymotion/dailymotion-sdk-php/pulls) once you're done! And again, if you think that something's wrong, don't hesitate to [report any issue](https://github.com/dailymotion/dailymotion-sdk-php/issues).
