# Token Type Manager

The token type manager must implement the `OAuth2\Token\TokenTypeManagerInterface` interface.
This library provides a fully featured manager. You just have to create an instance of `OAuth2\Token\TokenTypeManager`:

```php
<?php

use OAuth2\Token\TokenTypeManager;

$token_type_manager = new TokenTypeManager($exception_manager); // We suppose that $exception_manager is a valid exception manager
```

## Multiple Token Type Support

This manager is able to support multiple token types.
You must add at least one token type.

```php
<?php

// We suppose that $token_type is a valid token type instance
// The second argument sets the token type as the default token type.
$token_type_manager->addTokenType($token_type, true);
```

### Bearer Token Type

The `Bearer Token Type` (see [RFC6750](https://tools.ietf.org/html/rfc6750)) is most common token type.

Please read [this page](bearer.md) to know how to create and use this component.

### MAC Token Type

The `MAC Token Type` is an authentication scheme that uses a message authentication code (MAC) algorithm to provide cryptographic verification of the HTTP requests.
It is more secured than the previous token type as each request is signed by the client.
If the access token is stolen, it cannot be used as a valid request must be signed.

Please note that this specification is not stable and seems abandoned.
This library provides a MAC Token Type support, but it is limited to the [revision 2 of the specification](https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-02).

Please read [this page](mac.md) to know how to create and use this component.

### POP Token Type

This token type is not supported at the moment.

For more information, please follow the links hereafter:

* https://tools.ietf.org/html/draft-ietf-oauth-pop-architecture
* https://tools.ietf.org/html/draft-ietf-oauth-pop-key-distribution
* [RFC7800: Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)](https://tools.ietf.org/html/rfc7800)

# Token Type Restrictions Per Client

A client can ask for an access token with a specific token type per request.
this feature is useful if the default token type is `Bearer` and for security purpose the client prefer a `MAC` token.

To avoid malicious clients to ask for a weak token type (e;g; `Bearer` token) whereas the legit one uses `POP` token,
the client can restrict the list of allowed token types isuued by the authorization server.

With the example below, the client is not allowed to get a `Bearer` token.
If the default token type is `Bearer`, then the client must add the desired token type on each request (e.g. `token_type=POP`).

```php
<?php

//We suppose that the variable $client is a valid object that implements \OAuth2\Client\ClientInterface
$client->set('token_types', ['MAC', 'POP']);
```
