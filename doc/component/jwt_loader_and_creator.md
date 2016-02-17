JWT Creator And JWT Loader
==========================

For components that need to create JWT or to load them, you will have to inject a `JWTLoader` or a `JWTCreator` object.

In general, you do not need to use them as they are directly used by components. You just have to indicate algorithms you want to support
and claims you want to check.

# The JWTCreator

This service will create JWS (signed JWT) or JWE (encrypted JWT).

```php
use OAuth2\Util\JWTCreator;

$jwt_creator = new JWTCreator(
    ['RS256', 'RS512', 'ES256', 'ES512']                                // Signature algorithms,
    ['A128GCMKW' , 'A256GCMKW', 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256',], // Key encryption algorithms,
    ['A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512',]           // Content encryption algorithms,
    ['DEF']                                                             // Compression methods
);
```

Please note that the encryption algorithms parameters are not mandatory. They must only be set if you want to support encrypted JWT.
The compression methods enable compressed payload support. By default, the `DEF` (deflate) method is enabled.

# The JWTLoader

This service is used to load assertions or tokens. Its instantiation is very similar to the JWTCreator, except that you need
to inject a service to verify claims.

The Jose library provides a very simple claim checker manager able to check the following claims:

* `exp`: Expiration claim
* `iat`: Issued At claim
* `nbf`: Not Before claim

```php
use Jose\ClaimChecker\ClaimCheckerManager;

$claim_checker_manager = new ClaimCheckerManager();
```

We recommend you to extend it and check other claims, especially the audience claim (`aud`).

```php
use Jose\ClaimChecker\AudienceChecker;

$claim_checker_manager->addClaimChecker(new AudienceChecker('https://my.authorization.server'));
```

You can create new claim checkers by implementing the interface `Jose\ClaimChecker\ClaimCheckerInterface`.

Now that you claim checker manager is ready, you can create your JWTLoader service.

```php
use OAuth2\Util\JWTLoader;

$jwt_loader = new JWTLoader(
    $claim_checker_manager,                                             // The claim checker manager
    ['RS256', 'RS512', 'ES256', 'ES512']                                // Signature algorithms,
    ['A128GCMKW' , 'A256GCMKW', 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256',], // Key encryption algorithms,
    ['A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512',]           // Content encryption algorithms,
    ['DEF']                                                             // Compression methods
);
```
