Dailymotion PHP SDK
===================

This repository contains the official open source PHP SDK that allows you to access the Dailymotion
API from your website.

Usage
-----

The Dailymotion API requires OAuth 2.0 authentication in order to be used. This library implements
three granting methods of OAuth 2.0 for different kind of usages.

### Token Grant Type

This mode is the mode you should use in most case. In this mode you redirect the user to an
authorization page on Dailymotion, and you script is called back once the end-user authorized you API
key to access the Dailymotion service on its behalf.

Here is a usage example:

    <?php

    $api = new Dailymotion($apiKey, $apiSecret);
    $api->setGrantType(Dailymotion::GRANT_TYPE_TOKEN)

    try
    {
        $result = $api->call($method, $arguments);
    }
    catch (DailymotionAuthRequiredException $e)
    {
        // Redirect the user to the Dailymotion authorization page
        header('Location: ' . $api->getAuthorizationUrl());
        return;
    }
    catch (DailymotionAuthRefusedException $e)
    {
        // handle case when user refused to authorize
        // <YOUR CODE>
    }

### Password Grant Type

If you PHP application isn't a web application and cannot redirect the user to the Dailymotion
authorization page, the password grant type can be used. With this grant type you have the
responsibility to ask the user for its credentials. Make sure you API secret remains secret though.

    <?php

    $api = new Dailymotion($apiKey, $apiSecret);

    if (isset($_POST['username']) && isset($_POST['password']))
    {
        $api->setGrantType(Dailymotion::GRANT_TYPE_PASSWORD,
                           array('username' => $_POST['username'], 'password' => $_POST['password']));
    }

    try
    {
        $result = $api->call($method, $arguments);
    }
    catch (DailymotionAuthRequiredException $e)
    {
        // show username/password prompt
        // <YOUR CODE>
    }


### None Grant Type

If you don't need to access the Dailymotion API on behalf of a user because, for instance, you plan to
only access public data, you can use the NONE grant type. With this grant type, you will only have
access to public data or private date of the user owning the API key.

    <?php

    $api = new Dailymotion($apiKey, $apiSecret);
    $api->setGrantType(Dailymotion::GRANT_TYPE_NONE);
    $result = $api->call($method, $arguments);

Feedback
--------

We are relying on the [GitHub issues tracker][issues] linked from above for feedback. File bugs or
other issues [here][issues].

[issues]: http://github.com/dailymotion/dailymotion-sdk-php/issues