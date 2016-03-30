Token Type Manager
==================

The token type manager must implement the `OAuth2\Token\TokenTypeManagerInterface` interface.
This library provides a fully featured manager. You just have to create an instance of `OAuth2\Token\TokenTypeManager`:

```php
use OAuth2\Token\TokenTypeManager;

$token_type_manager = new TokenTypeManager($exception_manager); // We suppose that $exception_manager is a valid exception manager
```

# Token Type Support

This manager is able to support multiple token types.
You must add at least one token type

##  Bearer Token Type

The `Bearer Token Type` (see [RFC6750](https://tools.ietf.org/html/rfc6750)) is most common token type.
It is not secured and can be used by an other application when stolen.

Please read [this page](bearer.md) to know how to create and use this component.

##  MAC Token Type

The `MAC Token Type` is an authentication scheme that uses a message authentication code (MAC) algorithm to provide cryptographic verification of the HTTP requests.
It is more secured than the previous token type as each request is signed by the client. When stolen, it can be used without additional information.

Please note that this specification is not yet stable. This library provides a MAC Token Type support, but it is limited to the [revision 2 of the specification](https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-02). No update will be made until this specification has not reach maturity.

Please read [this page](mac.md) to know how to create and use this component.

##  POP Token Type

This token type is not supported at the moment.

For more information, please follow the links hereafter:

* https://tools.ietf.org/html/draft-ietf-oauth-pop-architecture
* https://tools.ietf.org/html/draft-ietf-oauth-pop-key-distribution
* https://tools.ietf.org/html/draft-ietf-oauth-proof-of-possession

# Token Type Per Client

This feature is not yet available.

However, in some cases, clients can ask for a specific token type on access token requests using the parameter `token_type`.
This feature is described on grant type pages.