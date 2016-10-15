# Response Mode Manager

The RFC6749 introduced two response modes:

- Query: `OAuth2\ResponseMode\QueryResponseMode`
- Fragment: `OAuth2\ResponseMode\FragmentResponseMode`

The OpenID Connect specification also introduces the following response mode:

- Form Post: `OAuth2\ResponseMode\FormPostResponseMode`

These response modes are used by the response types you enabled.

To get a response mode manager, just create a class that implement the `OAuth2\ResponseMode\ResponseModeManagerInterface`
or use the ready-to-use class provided by this bundle: `OAuth2\ResponseMode\ResponseModeManager`.

Then, add the response modes you want to use.

```php
<?php

use OAuth2\ResponseMode\FragmentResponseMode;
use OAuth2\ResponseMode\FormPostResponseMode;
use OAuth2\ResponseMode\QueryResponseMode;
use OAuth2\ResponseMode\ResponseModeManager;

$response_mode_manager = new ResponseModeManager();
$response_mode_manager->addResponseMode(new QueryResponseMode());
$response_mode_manager->addResponseMode(new FragmentResponseMode());
$response_mode_manager->addResponseMode(new FormPostResponseMode());
```

## Custom Response Mode

All response mode classes implement the `OAuth2\ResponseMode\ResponseModeInterface` class.
You can create your own response mode if you need.

## Override The Default Response Mode

In some specific cases, you may need to use another response mode than the default one.
For example you want to use the Authorization Code Grant Type (that uses the Query response mode) with the Form Post response mode.

This library supports this behaviour, however, as mentioned in the [Authorization Request](http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) section of the OpenID Connect specification,
the `response_mode` parameter *is NOT RECOMMENDED when the Response Mode that would be requested is the default mode specified for the Response Type.*

Please look at the [Response Mode Parameter Checker](../endpoint/authorization.md) in the authorization endpoint documentation.
