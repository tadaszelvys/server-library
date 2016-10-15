# Authorization Endpoint

The authorization endpoint is needed for every response types (e.g. Implicit or Authorization Code grants).
It displays a consent screen with a form. The resource owner (a user) has to accept or deny the authorization request.

Authorization requests and their parameters are loaded and verified by the Authorization Request Loader and the Authorization Factory.
Each parameter, if supported, is verified is checkers.

Authorization endpoint can load extensions to enhance it. Some extensions are provided by this library.

## The Authorization Request Loader

The Authorization Request Loader will try to load the authorization request from the server request.
If loaded, the result is an instance of the `OAuth2\Endpoint\Authorization\Authorization` class.

The Authorization Request Loader must implement the `OAuth2\Endpoint\Authorization\AuthorizationRequestLoaderInterface` interface.
This library provide the `OAuth2\Endpoint\Authorization\AuthorizationRequestLoader` that implements this interface.

```php
<?php

use OAuth2\Endpoint\Authorization\AuthorizationRequestLoader;

$request_loader = new AuthorizationRequestLoader($client_manager, $exception_manager);
$request_loader->
```

### Authorization Request Object Support

### Authorization Request Object By Reference Support

## The Authorization Factory

## The Authorization Endpoint

### Pre-Configured Authorizations Support
