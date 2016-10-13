# JWT Creator And JWT Loader

For components that need to create JWT or to load them, you will have to inject a `JWTLoader` or a `JWTCreator` object.

In general, you do not need to use them as they are directly used by components. You just have to indicate algorithms you want to support
and claims you want to check.

## The JWTCreator

This service will create JWS (signed JWT) or JWE (encrypted JWT) if encryption is enabled.

```php
use OAuth2\Util\JWTCreator;

$jwt_creator = new JWTCreator(
    ['RS256', 'RS512', 'ES256', 'ES512'] // Supported signature algorithms
);

// If you want to enable encryption support
$jwt_creator->enableEncryptionSupport(
    ['A128GCMKW' , 'A256GCMKW', 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256'], // Key encryption algorithms,
    ['A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512']           // Content encryption algorithms
);
```

## The JWTLoader

This service is used to load assertions or tokens. Its instantiation is very similar to the JWTCreator, except that you need
to inject a service to verify claims.

The Jose library provides a very simple claim checker manager able to check every claims you want (services have to be injected).

```php
use Jose\Checker\AudienceChecker;
use Jose\Factory\CheckerManagerFactory;

// We want to check the claims 'exp', 'iat', 'nbf'.
// We also want to check the 'crit' header.
// The factory allow us to add the claims and headers to check very easily.
$checker = CheckerManagerFactory::createClaimCheckerManager(
    ['exp', 'iat', 'nbf'],
    ['crit']
);

// We also want to check the 'aud' claim.
$checker->addClaimChecker(new AudienceChecker('https://my.authorization.server'));

```

Now that our checker manager is ready, we can create your JWTLoader service.

```php
use OAuth2\Util\JWTLoader;

$jwt_loader = new JWTLoader(
    $claim_checker_manager,              // The claim checker manager
    ['RS256', 'RS512', 'ES256', 'ES512'] // Signature algorithms
);

// We can enable the encryption support
$jwt_loader->enableEncryptionSupport(
    ['A128GCMKW' , 'A256GCMKW', 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256'], // Key encryption algorithms,
    ['A128GCM', 'A256GCM', 'A128CBC-HS256', 'A256CBC-HS512']           // Content encryption algorithms
```

**Your JWTLoader and JWTCreator should use the same algorithms. You should also use these services with all components that use them.**
