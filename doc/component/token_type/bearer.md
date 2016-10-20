# Bearer Token Type

The `Bearer Token Type` (see [RFC6750](https://tools.ietf.org/html/rfc6750)) is most common token type.

It uses three ways to authenticate the client passing the access token:

* In the request authentication header,
* In the query string,
* In the request body.

The first way is enabled by default. Passing the access token in the query string or request body are disabled by default as these methods are not recommended.

Examples:

```php
use OAuth2\Token\BearerToken;

$bearer_token = new BearerToken();

$token_type_manager->addTokenType($bearer_token); // We suppose that $token_type_manager is an instance of a `OAuth2\Token\TokenTypeManagerInterface`.
```

You can also enable other authentication methods:

```php
use OAuth2\Token\BearerToken;

$bearer_token = new BearerToken();
$bearer_token->enableAuthenticationUsingRequestBody();
$bearer_token->enableAuthenticationUsingQueryStringAllowed();

$token_type_manager->addTokenType($bearer_token);
```

Examples of clients requests are available in the [RFC6750 section 2.1, 2.2 and 2.3](https://tools.ietf.org/html/rfc6750#section-2).

In case you want to indicate the realm, you can set it as first argument of the constructor:

```php
use OAuth2\Token\BearerToken;

$bearer_token = new BearerToken('My Realm');
```

The `realm` parameter is described in the [RFC6750 section 3](https://tools.ietf.org/html/rfc6750#section-3).
