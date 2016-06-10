JWT Access Token Manager
========================

This access token manager will create access tokens based on JSON Web Token (JWT).
It does not need a database as they contain digitally signed claims.
The Authorization and Resource servers can directly verify signature using key materials.

These tokens can also be encrypted to prevent leak of sensitive data. *We highly recommend to enable the access token encryption feature, especially if you use the OpenId Connect extension with pairwise subject support*.

# Algorithms and Keys

To use this access token manager, you have to define an algorithm and a key (private or symmetric) to digitally sign the tokens.

## Access Token Signature

Thanks to [spomky-labs/jose](https://github.com/Spomky-Labs/jose), this library is able to support the following signature algorithms:

* HS256, HS384, HS512 (require symmetric key)
* ES256, ES384, ES512 (require private EC key)
* RS256, RS384, RS512 (require private RSA key)
* PS256, PS384, PS512 (require private RSA key)
* Ed25519 (require octet key pair key)

We recommend you to use `RS512` algorithm as it is quite fast, secured and uses a public/private (RSA) key pair.

### Signature Keys

The key used to sign the access tokens must be in `JWK` format. Again, thanks to [spomky-labs/jose](https://github.com/Spomky-Labs/jose), you will be able to create such keys using the `Jose\Factory\JWKFactory` from various sources.

#### Symmetric Keys

*If you decide to use this kind of keys, we highly recommend you to encrypt the access tokens.*

Examples:

```php
use Jose\Object\JWK;
use Base64Url\Base64Url;

$symmetric_key = new JWK(
    'kty' => 'oct',   // The type of the key. Must not be changed.
    'kid' => 'key1',  // Key ID. Not mandatory but highly recommended.
    'use' => 'sig',   // Indicates that the key is used to sign. Not mandatory but highly recommended.
    'alg' => 'HS256', // Indicates that the key can only be used with HS256 algorithm. Not mandatory but highly recommended.
    'k'   => Base64Url::encode('This is my super secret key with a lot of entropy.'), // The key encoded in Base64 Url Safe
);
```

#### Private RSA Keys

Example:

```php
$private_key = JWKFactory::createFromKeyFile(
    '/path/to/my/RSA/private.key',     // Path to your key file
    'password',                        // Password if the key is encrypted (else null)
    [
        'kid' => 'My Private RSA key', // Key ID. Not mandatory but highly recommended.
        'use' => 'sig',                // Indicates that the key is used to sign. Not mandatory but highly recommended.
        'alg' => 'RS256',              // Indicates that the key can only be used with RS256 algorithm. Not mandatory but highly recommended.
    ]
);
```

#### Private EC Keys

Example:

```php
$private_key = JWKFactory::createFromKeyFile(
    '/path/to/my/EC/private.key',      // Path to your key file
    'password',                        // Password if the key is encrypted (else null)
    [
        'kid' => 'My Private RSA key', // Key ID. Not mandatory but highly recommended.
        'use' => 'sig',                // Indicates that the key is used to sign. Not mandatory but highly recommended.
        'alg' => 'ES256',              // Indicates that the key can only be used with RS256 algorithm. Not mandatory but highly recommended.
    ]
);
```

# The JWT Access Token Manager

Now you have your keys, you can create an instance of the JWT Access Token Manager `OAuth2\Token\JWTAccessTokenManager`.

```php
use OAuth2\Token\JWTAccessTokenManager;

$jwt_access_manager = new JWTAccessTokenManager(
    $jwt_creator, // The JWT Creator service
    $jwt_loader,  // The JWT Loader service
    'HS512',      // The algorithm used to sign our JWT Access Tokens
    new JWK([     // The key used to sign
        'kid' => 'My signature key',
        'use' => 'sig',
        'alg' => 'HS512',
        'kty' => 'oct',
        'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
    ]),
    $this->issuer // The issuer of the token (i.e. the authorization serve URL).
);
```

*Important note: the JWTLoader and JWTCreator services MUST support the signature algorithm you want to use*

## Encrypted Access Tokens

You can enable the access token encryption if you want to protect information stored in the payload.

```php
$jwt_access_manager->enableAccessTokenEncryption(
    'A256KW',        // Key encryption algorithm
    'A256CBC-HS512', // Content encryption algorithm
    new JWK([        // Key used to encrypt
        'kid' => 'JWK1',
        'use' => 'enc',
        'kty' => 'oct',
        'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
    ])
);
```

## Encryption And Resource Servers

This library is designed to allow multiple resource servers to receive access tokens, but this feature is not yet supported.
When resource servers need to know if the access token is still valid, they must use the introspection endpoint.

More details will be added when this feature will be implemented.
