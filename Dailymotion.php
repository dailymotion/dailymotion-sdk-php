<?php

/**
 * Provides access to the Dailymotion Graph API.
 *
 * @author Olivier Poitrey <rs@dailymotion.com>
 * @author Nicolas Grevet <nicolas.grevet@dailymotion.com>
 * @author Samir Amzani <samir.amzani@dailymotion.com>
 */
class Dailymotion
{
    /**
     * Current version number of this SDK.
     * @var string Version number
     */
    const VERSION = '1.6.5';

    /**
     * An authorization is requested to the end-user by redirecting it to an authorization page hosted
     * on Dailymotion. Once authorized, a refresh token is requested by the API client to the token
     * server and stored in the end-user's cookie (or other storage technique implemented by subclasses).
     * The refresh token is then used to request time limited access token to the token server.
     * @var int
     */
    const GRANT_TYPE_AUTHORIZATION = 1;

    /**
     * @deprecated since 2010-11-03
     * @see Dailymotion::GRANT_TYPE_AUTHORIZATION
     * @var int
     */
    const GRANT_TYPE_TOKEN = 1;

    /**
     * This grant type is a 2 legs authentication: it doesn't allow to act on behalf of another user.
     * With this grant type, all API requests will be performed with the user identity of the API key owner.
     * @var int
     */
    const GRANT_TYPE_CLIENT_CREDENTIALS = 2;

    /**
     * @deprecated since 2010-12-14
     * @see Dailymotion::GRANT_TYPE_CLIENT_CREDENTIALS
     * @var int
     */
    const GRANT_TYPE_NONE = 2;

    /**
     * This grant type allows to authenticate an end-user by directly providing its credentials.
     * This profile is highly discouraged for web-server workflows. If used, the username and password
     * *MUST NOT* be stored by the client.
     * @var int
     */
    const GRANT_TYPE_PASSWORD = 3;

    /**
     * Type of display for the OAuth authorization.
     * @var string
     */
    const DISPLAY_PAGE = 'page';
    const DISPLAY_POPUP = 'popup';
    const DISPLAY_MOBILE = 'mobile';

    /**
     * Maximum number of redirections to follow when not in `safe_mode` or `open_basedir`.
     * @var int
     */
    const CURLOPT_MAXREDIRS = 3;

    /**
     * Name of the cookie containing the session.
     * @var string
     */
    const SESSION_COOKIE = 'dms_%s';

    /**
     * Activate debug output.
     * @var boolean
     */
    public $debug = false;

    /**
     * Maximum number of seconds allowed for each HTTP request to complete.
     * @var int
     */
    public $timeout = 5;

    /**
     * Maximum number of seconds to wait for connection establishment of HTTP requests.
     * @var int
     */
    public $connectionTimeout = 2;

    /**
     * An HTTP proxy to tunnel HTTP requests through (format: `hostname[:port]`).
     * @var string
     */
    public $proxy = null;

    /**
     * Username and password for the HTTP proxy (format: `user:password`).
     * @var string
     */
    public $proxyCredentials = null;

    /**
     * The Dailymotion API endpoint URL.
     * @var string
     */
    public $apiEndpointUrl = 'https://api.dailymotion.com';

    /**
     * The Dailymotion OAuth authorization server endpoint URL.
     * @var string
     */
    public $oauthAuthorizeEndpointUrl = 'https://www.dailymotion.com/oauth/authorize';

    /**
     * The Dailymotion OAuth token server endpoind URL.
     * @var string
     */
    public $oauthTokenEndpointUrl = 'https://api.dailymotion.com/oauth/token';

    /**
     * Domain name of the cookie used to store the session.
     * @var string
     */
    public $cookieDomain = null;

    /**
     * Life time (in seconds) of the cookie used to store the session.
     * @var int
     */
    public $cookieLifeTime = 31536000; // 1 year

    /**
     * Type of the current OAuth2 authorization attempt.
     * @var int
     */
    protected $grantType = null;

    /**
     * Information about the current OAuth2 authorization attempt.
     * @var array
     */
    protected $grantInfo = array();

    /**
     * Session information for the current OAuth2 authorization attempt.
     * @var array
     */
    protected $session = array();

    /**
     * Whether to store the session information for the current OAuth2 authorization attempt or not.
     * @var boolean
     */
    protected $storeSession = true;

    /**
     * If the current server supports it, we follow redirects.
     * @var boolean
     */
    protected $followRedirects;

    /**
     * List of query parameters that get automatically dropped when rebuilding the current URL.
     * @var array
     */
    protected static $DROP_QUERY_PARAMS = array(
        'code',
        'scope',
        'error',
        'error_description',
        'error_uri',
        'state',
        'uid',
        'sig',
    );

    /**
     * Change the default grant type.
     * To create an API key/secret pair, go to: http://www.dailymotion.com/profile/developer
     *
     * @param int    $type      Can be one of `Dailymotion::GRANT_TYPE_AUTHORIZATION`,
     *                          `Dailymotion::GRANT_TYPE_CLIENT_CREDENTIALS` or `Dailymotion::GRANT_TYPE_PASSWORD`.
     * @param string $apiKey    Client API key.
     * @param string $apiSecret Client API secret.
     * @param array  $scope     Permission scope requested.
     *                          See: http://developer.dailymotion.com/documentation#extended-oauth-permissions
     *                          for a list of available permissions. To requested several scope keys, provide several
     *                          scopes in the array.
     * @param array  $info      Information associated to the chosen grant type.
     *
     * $info keys:
     * - redirect_uri: If `$type` is `Dailymotion::GRANT_TYPE_AUTHORIZATION`, this key can be provided.
     *                 If omitted, the current URL will be used. Make sure this value stays the same
     *                 before the user is redirect to the authorization page and after the authorization
     *                 page redirects to this URI (the token server will change this).
     * - username:     If `$type` is `Dailymotion::GRANT_TYPE_PASSWORD`, end-user credentials are required.
     * - password:     If `$type` is `Dailymotion::GRANT_TYPE_PASSWORD`, end-user credentials are required.
     *
     * @throws DailymotionAuthRequiredException If no `$info` values are provided and no valid session is available.
     * @throws InvalidArgumentException         If grant type is not supported or required grant info is missing.
     * @return Dailymotion `$this`
     */
    public function setGrantType($type, $apiKey, $apiSecret, array $scope = array(), array $info = array())
    {
        if ($type === null)
        {
            $this->grantType = null;
            $this->grantInfo = array();
        }
        else
        {
            switch ($type)
            {
                case self::GRANT_TYPE_AUTHORIZATION:
                    if (!isset($info['redirect_uri']))
                    {
                        $info['redirect_uri'] = $this->getCurrentUrl();
                    }
                    break;

                case self::GRANT_TYPE_CLIENT_CREDENTIALS:
                case self::GRANT_TYPE_PASSWORD:
                    break;

                default:
                    throw new InvalidArgumentException('Invalid grant type: ' . $type);
            }
            if (empty($apiKey))
            {
                throw new InvalidArgumentException('Missing API key');
            }
            elseif (empty($apiSecret))
            {
                throw new InvalidArgumentException('Missing API secret');
            }
            $info['scope']  = $scope;
            $info['key']    = (string) $apiKey;
            $info['secret'] = (string) $apiSecret;

            $this->grantType = (int) $type;
            $this->grantInfo = $info;
        }
        return $this;
    }

    /**
     * Get an authorization URL for use with redirects. By default, full page redirect is assumed.
     * If you are using a generated URL with a `window.open()` call in Javascript, you can pass in
     * `Dailymotion::DISPLAY_POPUP` for `$display`.
     *
     * @param string $display Can either be `Dailymotion::DISPLAY_PAGE` (default, full page),
     *                        `Dailymotion::DISPLAY_POPUP` or `Dailymotion::DISPLAY_MOBILE`.
     * @return string         Authorization URL for use with redirects.
     */
    public function getAuthorizationUrl($display = self::DISPLAY_PAGE)
    {
        if ($this->grantType !== self::GRANT_TYPE_AUTHORIZATION)
        {
            throw new RuntimeException('This method can only be used with `AUTHORIZATION` grant type.');
        }
        return $this->oauthAuthorizeEndpointUrl . '?' . http_build_query(
            array(
                'response_type' => 'code',
                'client_id'     => $this->grantInfo['key'],
                'redirect_uri'  => $this->grantInfo['redirect_uri'],
                'scope'         => implode(chr(32), $this->grantInfo['scope']),
                'display'       => $display,
            ),
            null,
            '&'
        );
    }

    /**
     * Get the file path with the cURL format.
     * PHP 5.5 introduced a CurlFile object that deprecates the old `@filename` syntax.
     * See: https://wiki.php.net/rfc/curl-file-upload
     *
     * @param $filePath Path to the file to upload on the local filesystem.
     * @return mixed cURL file path.
     */
    protected function getCurlFile($filePath)
    {
        if (function_exists('curl_file_create'))
        {
            return curl_file_create($filePath);
        }
        else
        {
            return sprintf("@%s", $filePath);
        }
    }

    /**
     * Upload a file on Dailymotion's servers and generate an URL to be used with API methods.
     * Caution: This does not create a video on Dailymotion, it only uploads a file to Dailymotion's servers for you to
     * use as the `url` field of a video object. If your video is already online, you can skip this step and move on to:
     * ```
     * Dailymotion::post('/me/videos', array(
     *   'title'     => 'My video title',
     *   'channel'   => 'My video channel',
     *   'tags'      => 'My video tags',
     *   'url'       => 'URL to my video file',
     *   'published' => true,
     * );
     * ```
     * @param string  $filePath        Path to the file to upload on the local filesystem.
     * @param string  $forceHostname   Force a specific Dailymotion server (not recommended).
     * @param string  &$progressUrl    If this variable is given, it will include the progress URL in it.
     * @param string  $callbackUrl     It will ping a given url once the upload is finished
     * @return string                  URL of the file on Dailymotion's servers.
     * @throws DailymotionApiException If the API itself returned an error.
     */
    public function uploadFile($filePath, $forceHostname = null, &$progressUrl = null, $callbackUrl = null)
    {
        $params = array();
        if (!empty($callbackUrl))
        {
            $params['callback_url'] = $callbackUrl;
        }

        $result = $this->get('/file/upload', $params);
        $progressUrl = $result['progress_url'];
        if (!empty($forceHostname))
        {
            $result['upload_url'] = preg_replace('#://[^/]+/#', "://{$forceHostname}/", $result['upload_url']);
        }
        // Temporarily remove the timeout for uploads
        $timeout = $this->timeout;
        $this->timeout = null;

        // Upload the file to Dailymotion's servers
        $result = json_decode(
            $this->httpRequest($result['upload_url'], array('file' => $this->getCurlFile($filePath))),
            true
        );
        $this->timeout = $timeout;

        if (isset($result['error']))
        {
            throw new DailymotionApiException($result['error']['message'], $result['error']['code']);
        }
        return $result['url'];
    }

    /**
     * Alias for `Dailymotion::call("GET {$path}", $args)`.
     * @see Dailymotion::call()
     */
    public function get($path, $args = array())
    {
        return $this->call("GET {$path}", $args);
    }

    /**
     * Alias for `Dailymotion::call("POST {$path}", $args)`.
     * @see Dailymotion::call()
     */
    public function post($path, $args = array())
    {
        return $this->call("POST {$path}", $args);
    }

    /**
     * Alias for `Dailymotion::call("DELETE {$path}", $args)`.
     * @see Dailymotion::call()
     */
    public function delete($path, $args = array())
    {
        return $this->call("DELETE {$path}", $args);
    }

    /**
     * Call a remote endpoint on the API.
     *
     * @param string $resource API endpoint to call.
     * @param array  $args     Associative array of arguments.
     *
     * @throws DailymotionApiException          If the API itself returned an error.
     * @throws DailymotionAuthException         If we can't authenticate the request.
     * @throws DailymotionAuthRequiredException If no authentication info is available.
     * @throws DailymotionTransportException    If a network error occurs during the request.
     *
     * @return mixed Endpoint call response
     */
    public function call($resource, $args = array())
    {
        $headers = array('Content-Type: application/json');
        $payload = json_encode(array(
            'call' => $resource,
            'args' => $args,
        ));
        $statusCode = null;
        try
        {
            $result = json_decode(
                $this->oauthRequest(
                    $this->apiEndpointUrl,
                    $payload,
                    $this->getAccessToken(),
                    $headers,
                    $statusCode
                ),
                true
            );
        }
        catch (DailymotionAuthException $e)
        {
            if ($e->error === 'invalid_token')
            {
                // Retry by forcing the refresh of the access token
                $result = json_decode(
                    $this->oauthRequest(
                        $this->apiEndpointUrl,
                        $payload,
                        $this->getAccessToken(true),
                        $headers,
                        $statusCode
                    ),
                    true
                );
            }
            else
            {
                throw $e;
            }
        }
        if (empty($result))
        {
            throw new DailymotionApiException('Invalid API server response');
        }
        elseif ($statusCode !== 200)
        {
            throw new DailymotionApiException("Unknown error: {$statusCode}", $statusCode);
        }
        elseif (is_array($result) && isset($result['error']))
        {
            $message = isset($result['error']['message']) ? $result['error']['message'] : null;
            $code    = isset($result['error']['code'])    ? $result['error']['code']    : null;

            if ($code === 403)
            {
                throw new DailymotionAuthRequiredException($message, $code);
            }
            else
            {
                throw new DailymotionApiException($message, $code);
            }
        }
        elseif (!isset($result['result']))
        {
            throw new DailymotionApiException("Invalid API server response: no `result` key found.");
        }
        return $result['result'];
    }

    /**
     * Remove the right for the current API key to access the current user account.
     * @return Dailymotion `$this`
     */
    public function logout()
    {
        $this->call('/logout');
        $this->clearSession();
        return $this;
    }

    /**
     * Get the current access token. If no access token is available, try to obtain one using the refresh token
     * or code (depending on the state of the OAuth transaction). If no access token is available and no refresh
     * token or code can be found, an exception is thrown.
     *
     * @param boolean $forceRefresh Force the refresh of the access token, event if not expired.
     *
     * @throws DailymotionAuthRequiredException If we can't get an access token, client need to request end-user authorization.
     * @throws DailymotionAuthRefusedException  If the user refused the authorization.
     * @throws DailymotionAuthException         If an OAuth error occurred.
     *
     * @return string Access token or `null` if no grant type defined (un-authen API calls).
     */
    public function getAccessToken($forceRefresh = false)
    {
        if ($this->grantType === null)
        {
            // No grant type defined, the request won't be authenticated
            return null;
        }
        $session = $this->getSession();

        // Check if session is present and if it was created for the same grant type
        // i.e: if the grant type to create the session was `AUTHORIZATION` and the current grant type is
        // `CLIENT_CREDENTIALS`, we don't want to call the API on behalf of another user.
        if (!empty($session) && isset($session['grant_type']) && ((int) $session['grant_type'] === $this->grantType))
        {
            if (!$forceRefresh && isset($session['access_token']))
            {
                if (!isset($session['expires']) || (time() < $session['expires']))
                {
                    return $session['access_token'];
                }
                // else: Token expired
            }
            // No valid access token found, try to refresh it
            if (isset($session['refresh_token']))
            {
                $grantType = $session['grant_type'];
                $session = $this->oauthTokenRequest(array(
                    'grant_type'    => 'refresh_token',
                    'client_id'     => $this->grantInfo['key'],
                    'client_secret' => $this->grantInfo['secret'],
                    'scope'         => implode(chr(32), $this->grantInfo['scope']),
                    'refresh_token' => $session['refresh_token'],
                ));
                $session['grant_type'] = $grantType;
                $this->setSession($session);
                return $session['access_token'];
            }
        }
        try
        {
            if ($this->grantType === self::GRANT_TYPE_AUTHORIZATION)
            {
                $code  = filter_input(INPUT_GET, 'code');
                $error = filter_input(INPUT_GET, 'error');

                if (!empty($code))
                {
                    // We've been called back by authorization server
                    $session = $this->oauthTokenRequest(array(
                        'grant_type'    => 'authorization_code',
                        'client_id'     => $this->grantInfo['key'],
                        'client_secret' => $this->grantInfo['secret'],
                        'scope'         => implode(chr(32), $this->grantInfo['scope']),
                        'redirect_uri'  => $this->grantInfo['redirect_uri'],
                        'code'          => $code,
                    ));
                    $session['grant_type'] = $this->grantType;
                    $this->setSession($session);
                    return $session['access_token'];
                }
                elseif (!empty($error))
                {
                    $message = filter_input(INPUT_GET, 'error_description');
                    if ($error === 'access_denied')
                    {
                        $e = new DailymotionAuthRefusedException($message);
                    }
                    else
                    {
                        $e = new DailymotionAuthException($message);
                    }
                    $e->error = $error;
                    throw $e;
                }
                else
                {
                    // Ask the client to request end-user authorization
                    throw new DailymotionAuthRequiredException();
                }
            }
            elseif ($this->grantType === self::GRANT_TYPE_CLIENT_CREDENTIALS)
            {
                $session = $this->oauthTokenRequest(array(
                    'grant_type'    => 'client_credentials',
                    'client_id'     => $this->grantInfo['key'],
                    'client_secret' => $this->grantInfo['secret'],
                    'scope'         => implode(chr(32), $this->grantInfo['scope']),
                ));
                $session['grant_type'] = $this->grantType;
                $this->setSession($session);
                return $session['access_token'];
            }
            elseif ($this->grantType === self::GRANT_TYPE_PASSWORD)
            {
                if (!isset($this->grantInfo['username']) || !isset($this->grantInfo['password']))
                {
                    // Ask the client to request end-user credentials
                    throw new DailymotionAuthRequiredException();
                }
                $session = $this->oauthTokenRequest(array(
                    'grant_type'    => 'password',
                    'client_id'     => $this->grantInfo['key'],
                    'client_secret' => $this->grantInfo['secret'],
                    'scope'         => implode(chr(32), $this->grantInfo['scope']),
                    'username'      => $this->grantInfo['username'],
                    'password'      => $this->grantInfo['password'],
                ));
                $session['grant_type'] = $this->grantType;
                $this->setSession($session);
                return $session['access_token'];
            }
        }
        catch (DailymotionAuthException $e)
        {
            // clear session on error
            $this->clearSession();
            throw $e;
        }
    }

    /**
     * Set the session and store it if `$this->storeSession` is true.
     *
     * @param $session array the session to set
     * @return Dailymotion `$this`
     */
    public function setSession(array $session = array())
    {
        $this->session = $session;
        if ($this->storeSession)
        {
            $this->storeSession($session);
        }
        return $this;
    }

    /**
     * Get the session if any.
     * @return array Current session or an empty array if none found.
     */
    public function getSession()
    {
        if (empty($this->session))
        {
            $this->session = $this->readSession();
        }
        return $this->session;
    }

    /**
     * Clear the currently stored session.
     * @return Dailymotion `$this`
     */
    public function clearSession()
    {
        $this->setSession();
        return $this;
    }

    /**
     * Read the session from the session store.
     * Default storage is cookie, subclass can implement another storage type if needed.
     * Information stored in the session are useless without the API secret. Storing these information on the client
     * should thus be safe as long as the API secret is kept... secret.
     *
     * @return array Stored session or an empty array if none found.
     */
    protected function readSession()
    {
        $session    = array();
        $cookieName = sprintf(self::SESSION_COOKIE, $this->grantInfo['key']);
        $cookieValue = filter_input(INPUT_COOKIE, $cookieName);

        if (!empty($cookieValue))
        {
            parse_str(
                trim((get_magic_quotes_gpc() ? stripslashes($cookieValue) : $cookieValue), '"'),
                $session
            );
        }
        return $session;
    }

    /**
     * Store the given session to the session store.
     * Default storage is cookie, subclass can implement another storage type if needed.
     * Information stored in the session are useless without the API secret. Storing these information on the client
     * should thus be safe as long as the API secret is kept... secret.
     *
     * @param array $session Session to store, if nothing is passed, the current session is removed from the session store.
     * @return Dailymotion `$this`
     */
    protected function storeSession(array $session = array())
    {
        if (headers_sent())
        {
            if (php_sapi_name() !== 'cli')
            {
                error_log('Could not set session in cookie: headers already sent.');
            }
            return $this;
        }
        $cookieName = sprintf(self::SESSION_COOKIE, $this->grantInfo['key']);
        if (!empty($session))
        {
            $value   = '"' . http_build_query($session, null, '&') . '"';
            $expires = time() + $this->cookieLifeTime;
        }
        else
        {
            $cookieValue = filter_input(INPUT_COOKIE, $cookieName);
            if (empty($cookieValue))
            {
                // No need to remove an unexisting cookie
                return $this;
            }
            $value   = 'deleted';
            $expires = time() - 3600;
        }
        setcookie($cookieName, $value, $expires, '/', $this->cookieDomain);
        return $this;
    }

    /**
     * Perform a request to a token server complient with the OAuth 2.0 specification.
     *
     * @param array $args Arguments to send to the token server.
     * @throws DailymotionAuthException If the token server sends an error or invalid response.
     * @return array Cconfigured session.
     */
    protected function oauthTokenRequest(array $args)
    {
        $statusCode = null;
        $responseHeaders = array();
        $result = json_decode(
            $response = $this->httpRequest(
                $this->oauthTokenEndpointUrl,
                $args,
                null,
                $statusCode,
                $responseHeaders,
                true
            ),
            true
        );
        if (empty($result))
        {
            throw new DailymotionAuthException("Invalid token server response: {$response}");
        }
        elseif (isset($result['error']))
        {
            $message = isset($result['error_description']) ? $result['error_description'] : null;
            $e = new DailymotionAuthException($message);
            $e->error = $result['error'];
            throw $e;
        }
        elseif (isset($result['access_token']))
        {
            return array(
                'access_token'  => $result['access_token'],
                'expires'       => time() + $result['expires_in'],
                'refresh_token' => isset($result['refresh_token']) ? $result['refresh_token'] : null,
                'scope'         => isset($result['scope']) ? explode(chr(32), $result['scope']) : array(),
            );
        }
        else
        {
            throw new DailymotionAuthException('No access token found in the token server response');
        }
    }

    /**
     * Perform an OAuth 2.0 authenticated request.
     *
     * @param string $url the         URL to perform the HTTP request to.
     * @param string $payload         Encoded method request to POST.
     * @param string $accessToken     OAuth access token to authenticate the request with.
     * @param array  $headers         List of headers to send with the request (format `array('Header-Name: header value')`).
     * @param int   &$statusCode      Reference variable to store the response status code.
     * @param array &$responseHeaders Reference variable to store the response headers.
     *
     * @throws DailymotionAuthException      If an OAuth error occurs.
     * @throws DailymotionTransportException If a network error occurs during the request.
     *
     * @return string Response body.
     */
    protected function oauthRequest($url, $payload, $accessToken = null, $headers = array(), &$statusCode = null, &$responseHeaders = array())
    {
        if ($accessToken !== null)
        {
            $headers[] = "Authorization: Bearer {$accessToken}";
        }
        $result = $this->httpRequest(
            $url,
            $payload,
            $headers,
            $statusCode,
            $responseHeaders
        );
        switch ($statusCode)
        {
            case 401: // Invalid or expired token
            case 400: // Invalid request
            case 403: // Insufficient scope
                $error   = null;
                $message = null;
                $match   = array();

                if (preg_match('/error="(.*?)"(?:, error_description="(.*?)")?/', $responseHeaders['www-authenticate'], $match))
                {
                    $error   = $match[1];
                    $message = $match[2];
                }
                $e = new DailymotionAuthException($message);
                $e->error = $error;
                throw $e;
        }
        return $result;
    }

    /**
     * Perform an HTTP request by posting the given payload and returning the result.
     * Override this method if you don't want to use cURL.
     *
     * @param string  $url             URL to perform the HTTP request to.
     * @param mixed   $payload         Data to POST. If it's an associative array and `$encodePayload` is set to true,
     *                                 it will be url-encoded and the `Content-Type` header will automatically be set
     *                                 to `multipart/form-data`. If it's a string make sure you set the correct
     *                                 `Content-Type` header yourself.
     * @param array   $headers         List of headers to send with the request (format `array('Header-Name: header value')`).
     * @param int    &$statusCode      Reference variable to store the response status code.
     * @param array  &$responseHeaders Reference variable to store the response headers.
     * @param boolean $encodePayload   Whether or not to encode the payload if it's an associative array.
     *
     * @throws DailymotionTransportException If a network error occurs during the request.
     * @return string Response body
     */
    protected function httpRequest($url, $payload, $headers = null, &$statusCode = null, &$responseHeaders = array(), $encodePayload = false)
    {
        $payload = (is_array($payload) && (true === $encodePayload))
            ? http_build_query($payload, null, '&')
            : $payload;

        // Force removal of the Expect: 100-continue header automatically added by cURL
        $headers[] = 'Expect:';

        // cURL options
        $options = array(
            CURLOPT_CONNECTTIMEOUT => $this->connectionTimeout,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_PROXY          => $this->proxy,
            CURLOPT_PROXYUSERPWD   => $this->proxyCredentials,
            CURLOPT_USERAGENT      => sprintf('Dailymotion-PHP/%s (PHP %s; %s)', self::VERSION, PHP_VERSION, php_sapi_name()),
            CURLOPT_HEADER         => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_URL            => $url,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_NOPROGRESS     => !($this->debug && is_array($payload) && array_key_exists('file', $payload)),
        );
        // There is no constructor to this class and I don't intend to add one just for this (PHP 4 legacy and all).
        if (is_null($this->followRedirects))
        {
            // We use filter_var() here because depending on PHP's version, these ini_get() may or may not return:
            // true/false or even the strings 'on', 'off', 'true' or 'false' or folder paths... better safe than sorry.
            $this->followRedirects =
                (false === filter_var(ini_get('open_basedir'), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE))
                && (false === filter_var(ini_get('safe_mode'), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE));
        }
        // If the current server supports it, we follow redirects
        if ($this->followRedirects === true)
        {
            $options[CURLOPT_FOLLOWLOCATION] = true;
            $options[CURLOPT_MAXREDIRS]      = self::CURLOPT_MAXREDIRS;
        }
        $this->debugRequest($url, $payload, $headers);

        // Execute the cURL request
        $ch = curl_init();
        curl_setopt_array($ch, $options);
        $response = curl_exec($ch);

        // CURLE_SSL_CACERT error
        if (curl_errno($ch) == 60)
        {
            error_log('Invalid or no certificate authority found, using bundled information');
            curl_setopt($ch, CURLOPT_CAINFO, __DIR__ . '/dm_ca_chain_bundle.crt');
            $response = curl_exec($ch);
        }
        // Invalid empty response
        if ($response === false)
        {
            $e = new DailymotionTransportException(curl_error($ch), curl_errno($ch));
            curl_close($ch);
            throw $e;
        }
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        list($responseHeadersString, $payload) = explode("\r\n\r\n", $response, 2);
        strtok($responseHeadersString, "\r\n"); // skip status code

        while(($name = trim(strtok(":"))) && ($value = trim(strtok("\r\n"))))
        {
            $responseHeaders[strtolower($name)] = (isset($responseHeaders[$name])
                ? $responseHeaders[$name] . '; '
                : null) . $value;
        }
        $this->debugResponse($url, $payload, $responseHeaders);
        return $payload;
    }

    /**
     * Returns the current URL, stripping if of known OAuth parameters that should not persist.
     * @return string Current URL.
     */
    protected function getCurrentUrl()
    {
        $filters = array(
            'HTTPS'                  => FILTER_VALIDATE_BOOLEAN,
            'HTTP_SSL_HTTPS'         => FILTER_VALIDATE_BOOLEAN,
            'HTTP_X_FORWARDED_PROTO' => FILTER_SANITIZE_STRING,
            'HTTP_HOST'              => FILTER_SANITIZE_STRING,
            'REQUEST_URI'            => FILTER_SANITIZE_STRING,
        );
        // FastCGI seems to cause strange side-effects with unexpected NULL values when using INPUT_SERVER and
        // INPUT_ENV with the filter_input() and filter_input_array() functions, so we're using a workaround there.
        // See: http://fr2.php.net/manual/en/function.filter-input.php#77307
        if (PHP_SAPI === 'cgi-fcgi')
        {
            $values = $filters;
            array_walk($values, function (&$value, $key) { $value = isset($_SERVER[$key]) ? $_SERVER[$key] : null; });
            $values = filter_var_array($values, $filters);
        }
        else
        {
            $values = filter_input_array(INPUT_SERVER, $filters);
        }
        $secure = ($values['HTTPS'] || $values['HTTP_SSL_HTTPS'] || (strtolower($values['HTTP_X_FORWARDED_PROTO']) === 'https'));
        $scheme = $secure ? 'https://' : 'http://';

        $currentUrl = $scheme . $values['HTTP_HOST'] . $values['REQUEST_URI'];
        $parts      = parse_url($currentUrl);

        // Remove OAuth callback params
        $query = null;
        if (!empty($parts['query']))
        {
            $parameters = array();
            parse_str($parts['query'], $parameters);

            foreach(self::$DROP_QUERY_PARAMS as $name)
            {
                unset($parameters[$name]);
            }
            if (count($parameters) > 0)
            {
                $query = '?' . http_build_query($parameters, null, '&');
            }
        }
        // Use port if non default
        $port = (!empty($parts['port']) && (($secure) ? ($parts['port'] !== 80) : ($parts['port'] !== 443)))
            ? ":{$parts['port']}"
            : null;

        // Rebuild
        return $scheme . $parts['host'] . $port . $parts['path'] . $query;
    }

    /**
     * Debug an HTTP request on the current output.
     *
     * @param string $url     URL of the request.
     * @param mixed  $payload Payload sent with the request.
     * @param array  $headers Headers sent with the request.
     */
    protected function debugRequest($url, $payload, array $headers)
    {
        if ($this->debug)
        {
            // debug for xterm-compliant cli
            if (php_sapi_name() === 'cli')
            {
                echo PHP_EOL;
                echo "\e[1;33m>>>\e[0;33m [{$url}] \e[1;33m>>>\e[00m" . PHP_EOL;

                foreach ($headers as $value)
                {
                    $matches = array();
                    preg_match('#^(?P<key>[^:\s]+)\s*:\s*(?P<value>.*)$#S', $value, $matches);
                    echo "\e[1;34m{$matches['key']}: \e[0;34m{$matches['value']}\e[00m" . PHP_EOL;
                }
                echo PHP_EOL;
                echo (is_array($payload))
                    ? json_encode($payload, JSON_PRETTY_PRINT)
                    : ((is_null($json = json_decode($payload)))
                        ? $payload :
                        json_encode($json, JSON_PRETTY_PRINT)
                    );

                echo PHP_EOL;
            }
            // debug for the rest
            else
            {
                echo ">>> [{$url}] >>>" . PHP_EOL;
                $message = print_r(is_null($json = json_decode($payload)) ? $payload : $json, true);
                echo $message . (strpos($message, PHP_EOL) ? null : PHP_EOL);
            }
        }
    }

    /**
     * Debug an HTTP response on the current output.
     *
     * @param string $url     URL of the request.
     * @param mixed  $payload Payload sent with the request.
     * @param array  $headers Headers sent with the request.
     */
    protected function debugResponse($url, $payload, array $headers)
    {
        if ($this->debug)
        {
            // debug for xterm-compliant cli
            if (php_sapi_name() === 'cli')
            {
                echo PHP_EOL;
                echo "\e[1;33m<<<\e[0;33m [{$url}] \e[1;33m<<<\e[00m" . PHP_EOL;
                foreach ($headers as $key => $value)
                {
                    echo "\e[1;34m{$key}: \e[0;34m{$value}\e[00m" . PHP_EOL;
                }
                echo PHP_EOL;
                echo ($json = json_decode($payload, true)) == NULL ? $payload : json_encode($json, JSON_PRETTY_PRINT);
                echo PHP_EOL;
            }
            // debug for the rest
            else
            {
                echo "<<< [{$url}] <<<" . PHP_EOL;
                print_r(($json = json_decode($payload)) == NULL ? $payload : $json);
                echo PHP_EOL;
            }
        }
    }
}

class DailymotionApiException extends Exception {}
class DailymotionTransportException extends DailymotionApiException {}
class DailymotionAuthException extends DailymotionApiException {public $error = null;}
class DailymotionAuthRequiredException extends DailymotionAuthException {}
class DailymotionAuthRefusedException extends DailymotionAuthException {}
