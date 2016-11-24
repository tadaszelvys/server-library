# Authorization Endpoint

The authorization endpoint is needed for every response types (e.g. Implicit or Authorization Code grants).
It displays a consent screen with a form. The resource owner (a user) has to accept or deny the authorization request.

Authorization requests and their parameters are loaded and verified by the Authorization Request Loader and the Authorization Factory.
Each parameter, if supported, is verified is checkers.

Authorization endpoint can load extensions to enhance it. Some extensions are provided by this library.

## The Authorization Request Loader

The Authorization Request Loader will try to load the authorization request from the server request.

The Authorization Request Loader must implement the `OAuth2\Endpoint\Authorization\AuthorizationRequestLoaderInterface` interface.
This library provide the `OAuth2\Endpoint\Authorization\AuthorizationRequestLoader` that implements this interface.

```php
<?php

use OAuth2\Endpoint\Authorization\AuthorizationRequestLoader;

$request_loader = new AuthorizationRequestLoader($client_manager, $response_factory_manager);
```

### Authorization Request Object Support

The Authorization Request Loader provided by this library is able to support Request objects and Request Object by Reference.
You just have a JWT Loader and call the following methods. The `$mandatory_claims` is an array of strings that allows you to define which claims must be set on each Request Object.
We recommend you to such at least the `exp` claim.

```php
// Enable the Request Object support.
$mandatory_claims = ['exp'];
$request_loader->enableRequestObjectReferenceSupport($jwt_loader, $mandatory_claims);

// Enable the Request Object by Reference support.
// The previous method must be called before this one otherwise an exception is thrown.
$request_loader->enableRequestObjectReferenceSupport();
```

Request Objects may be encrypted. This feature is also supported by this Authorization Request Loader.
Just call the method `enableEncryptedRequestObjectSupport` with the following arguments:

- A JWKSet object with all shared or private keys used to decrypt the Request Objects
- A boolean. If true, then all Request Object must be encrypted.

The supported encryption algorithms are those set in the JWT Loader you used with the method `enableRequestObjectReferenceSupport`.

```php
$request_loader->enableEncryptedRequestObjectSupport($key_encryption_key_set, $require_encryption);
```

Clients may have registered Uris where they store the Request object by Reference.
To enforce all clients to register such Uri (highly recommended), you can call the following method:

```php
$request_loader->enableRequestUriRegistrationRequirement();
```

According to the OpenID Connect specification, the stored Uris MUST be secured.
You can disable this requirement and allow unsecured connections (HTTP connections or HTTPS with unverified certificates).
We DO NOT recommend the use of this method unless you know exactly what you are doing (e.g. performing tests).

```php
$request_loader->allowUnsecuredConnections();
```

## The Authorization Factory



## The Authorization Endpoint

### Pre-Configured Authorizations Support
