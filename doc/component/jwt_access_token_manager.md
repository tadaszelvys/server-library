# JWT Access Token Manager

This access token manager will create access tokens based on JSON Web Token (JWT).
It does not need a database as they contain digitally signed claims.
The Authorization and Resource servers can directly verify signature using key materials.

These tokens are also encrypted to prevent leak of sensitive data.

## Algorithms and Keys

To use this access token manager, you have to define,
- A signature algorithm,
- A key encryption algorithm,
- A content encryption algorithm,
- A key set with all signature keys (at least one key in the key set),
- A key set with all key encryption keys (at least one key in the key set).

### Signature Algorithm

Thanks to [spomky-labs/jose](https://github.com/Spomky-Labs/jose), this library is able to support the following signature algorithms:

* HS256, HS384, HS512 (require `oct` keys).
* ES256, ES384, ES512 (require `EC` keys).
* RS256, RS384, RS512 (require `RSA` keys).
* PS256, PS384, PS512 (require `RSA` keys).
* EdDSA with Ed25519 curve (requires `OKP` keys).

We recommend you to use `RS512` algorithm as it is quite fast and secured.

### Key Encryption Algorithm

The following key encryption algorithms:

* dir (requires `oct` keys).
* RSA1_5, RSA-OAEP, RSA-OAEP-256 (require `RSA` keys).
* ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW (require `EC` keys).
* A128KW, A192KW, A256KW (require `oct` keys).
* PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW (require `oct` keys).
* A128GCMKW, A192GCMKW, A256GCMKW (require `oct` keys). For performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto).
* EdDSA with X25519 curve (requires `OKP` keys). [Third party extension required](https://github.com/encedo/php-curve25519-ext).

We recommend you to use the `AxxxGCMKW` algorithm if you have the third party extension installed, otherwise the `RSA1_5` algorithm.

### Content Encryption Algorithms

* A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
* A128GCM, A192GCM, A256GCM. For performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto).

We recommend you to use the `AxxGCM` algorithm if you have the third party extension installed, otherwise any other algorithm.

### Key Sets Creation

The key set configuration you have to set depends on the algorithm you choose.
Hereafter some example of configurations you may use.

We highly recommend you to:
- Create rotatable key sets with at least 2 keys to allow you to change your keys without service interruption.
- Define additional parameters for your keys such as the `alg` and the `use` ones.

Please refer to the [spomky-labs/jose](https://github.com/Spomky-Labs/jose) documentation for more information.

#### `RSA` Key Set

With the following example, we will have a key set with 3 RSA keys.
Each key has 4096 bits size and is dedicated to signature operation with the `RS512` algorithm.

```php
<?php

use Jose\Factory\JWKFactory;

$signature_key_set = JWKFactory::createRotatableKeySet(
    '/path/to/the/keyset',
    [
        'kty'  => 'RSA',
        'use'  => 'sig',
        'alg'  => 'RS512',
        'size' => 4096,
    ],
    3
);
```

#### `oct` Key Set

With the following example, we will have a key set with 3 RSA keys.
Each key has 4096 bits size and is dedicated to signature/verification operations with the `RS512` algorithm.

```php
<?php

use Jose\Factory\JWKFactory;

$encryption_key_set = JWKFactory::createRotatableKeySet(
    '/path/to/the/keyset',
    [
        'kty'  => 'oct',
        'use'  => 'enc',
        'alg'  => 'A256GCMKW',
        'size' => 256,
    ],
    3
);
```

With the following example, we will have a key set with 3 octet keys.
Each key has 256 bits size and is dedicated to encryption/decryption operations with the `A256GCMKW` algorithm.

## The JWT Access Token Manager Object

Now that you have all algorithms and key sets, then you have to create an instance of the `OAuth2\Token\JWTAccessTokenManager` class.

```php
<?php

use OAuth2\Token\JWTAccessTokenManager;

$jwt_access_manager = new JWTAccessTokenManager(
    $jwt_creator,              // The JWT Creator service
    $jwt_loader,               // The JWT Loader service
    'HS512',                   // The algorithm used to sign our JWT Access Tokens
    $signature_key_set,        // The signature key set
    'A256GCMKW',               // The key encryption algorithm
    'AGCMKW',                  // The content encryption algorithm
    $encryption_key_set,       // The signature key set
    'https://www.example.com/' // The issuer of the token (i.e. the authorization server URL).
);
```

### Encryption And Resource Servers

This library is designed to allow multiple resource servers to receive access tokens, but this feature is not yet supported.
When resource servers need to know if the access token is still valid, they must use the introspection endpoint.

More details will be added when this feature will be implemented.
