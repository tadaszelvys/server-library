JWT Access Token Manager
========================

This access token manager will create access tokens base of JSON Web Token (JWT).
It does not need a database as they contain digitally signed claims.
The Authorization and Resource servers can directly verify signature using key materials.

These tokens can also be encrypted to prevent leak of sensitive data.

*Please note that if access tokens are encrypted, the authorization server will not be able to verify claims unless it is the audience of this token*

# Algorithms and Keys

To use this access token manager, you have to define an algorithm and a key (private or symmetric) to digitaly sign the tokens.

## Signature Algorithms

Thanks to [spomky-labs/jose](https://github.com/Spomky-Labs/jose), this library is able to support the following algorithms:

* HS256, HS384, HS512 (require symmetric key)
* ES256, ES384, ES512 (require private EC key)
* RS256, RS384, RS512 (require private RSA key)
* PS256, PS384, PS512 (require private RSA key)

We recommend you to use `RS512` algorithm as it is quite fast, secured and uses a public/private (RSA) key pair.

## Keys

The key used to sign the access tokens must be in `JWK` format. Again, thanks to [spomky-labs/jose](https://github.com/Spomky-Labs/jose), you will be able to create such keys using the `Jose\Factory\JWKFactory` from various sources.

### Symmetric Key


### Private RSA Key


### Private EC Key


## Encryption Algorithms

If you decide to encrypt the access tokens, you will have to choose two additional algorithms: the key encryption and the content encryption algorithms.

The supported algorithms are:

* Key Encryption Algorithms:
    * dir
    * RSA1_5, RSA-OAEP, RSA-OAEP-256
    * ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
    * A128KW, A192KW, A256KW
    * PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW
    * A128GCMKW, A192GCMKW, A256GCMKW
* Content Encryption Algorithms:
    * A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
    * A128GCM, A192GCM, A256GCM

We recommend you to use `RSA-OAEP-256` as key encryption algorithm and `A256CBC-HS512` as content encryption algorithm.
