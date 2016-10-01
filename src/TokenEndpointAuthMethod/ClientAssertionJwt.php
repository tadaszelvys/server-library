<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\TokenEndpointAuthMethod;

use Assert\Assertion;
use Jose\Factory\JWKFactory;
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

class ClientAssertionJwt implements TokenEndpointAuthMethodInterface
{
    use HasJWTLoader;
    use HasExceptionManager;

    /**
     * @var bool
     */
    private $encryption_required = false;

    /**
     * @var \Jose\Object\JWKSetInterface|null
     */
    private $key_encryption_key_set = null;

    /**
     * PasswordClientManager constructor.
     *
     * @param \Jose\JWTLoaderInterface                    $jwt_loader
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(JWTLoaderInterface $jwt_loader, ExceptionManagerInterface $exception_manager)
    {
        $this->setJWTLoader($jwt_loader);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @param bool                         $encryption_required
     * @param \Jose\Object\JWKSetInterface $key_encryption_key_set
     */
    public function enableEncryptedAssertions($encryption_required,
                                              JWKSetInterface $key_encryption_key_set)
    {
        Assertion::boolean($encryption_required);

        $this->encryption_required = $encryption_required;
        $this->key_encryption_key_set = $key_encryption_key_set;
    }

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms()
    {
        return $this->getJWTLoader()->getSupportedSignatureAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms()
    {
        return $this->getJWTLoader()->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms()
    {
        return $this->getJWTLoader()->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSchemesParameters()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request, &$client_credentials = null)
    {
        $client_assertion_type = RequestBody::getParameter($request, 'client_assertion_type');

        //We verify the client assertion type in the request
        if ('urn:ietf:params:oauth:client-assertion-type:jwt-bearer' !== $client_assertion_type) {
            return;
        }

        $client_assertion = RequestBody::getParameter($request, 'client_assertion');

        try {
            //We verify the client assertion exists
            Assertion::notNull($client_assertion, 'Parameter "client_assertion" is missing.');

            //We load the assertion
            $jwt = $this->getJWTLoader()->load(
                $client_assertion,
                $this->key_encryption_key_set,
                $this->encryption_required
            );

            $diff = array_diff(['iss', 'sub', 'aud', 'jti', 'exp'], array_keys($jwt->getClaims()));
            Assertion::eq(0, count($diff), sprintf('The following claim(s) is/are mandatory: "%s".', json_encode(array_values($diff))));
            Assertion::eq($jwt->getClaim('sub'), $jwt->getClaim('iss'), 'The claims "sub" and "iss" must contain the client public ID.');
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }

        $client_credentials = $jwt;

        return $jwt->getClaim('sub');
    }

    /**
     * {@inheritdoc}
     */
    public function isClientAuthenticated(ClientInterface $client, $client_credentials, ServerRequestInterface $request)
    {
        $jwk_set = $client->getPublicKeySet();
        if (!$jwk_set instanceof JWKSetInterface) {
            return false;
        }

        try {
            $this->getJWTLoader()->verify(
                $client_credentials,
                $jwk_set
            );
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedAuthenticationMethods()
    {
        return ['client_secret_jwt', 'private_key_jwt'];
    }

    /**
     * {@inheritdoc}
     */
    public function checkClientConfiguration(array $client_configuration, array &$metadatas)
    {
        if ('client_secret_jwt' === $client_configuration['token_endpoint_auth_method']) {
            Assertion::keyExists('client_secret', $client_configuration, 'The parameter "client_secret" must be set.');
            Assertion::string($client_configuration['client_secret'], 'The parameter "client_secret" must be a string.');
        } elseif ('private_key_jwt' === $client_configuration['token_endpoint_auth_method']) {
            Assertion::true(array_key_exists('jwks', $client_configuration) xor array_key_exists('jwks_uri', $client_configuration), 'The parameter "jwks" or "jwks_uri" must be set.');
            if (array_key_exists('jwks', $client_configuration)) {
                $jwks = new JWKSet($client_configuration['jwks']);
                Assertion::isInstanceOf($jwks, JWKSetInterface::class, 'The parameter "jwks" must be a valid JWKSet object.');
                $metadatas['jwks'] = $client_configuration['jwks'];
            } else {
                $jwks = JWKFactory::createFromJKU($client_configuration['jwks_uri']);
                Assertion::isInstanceOf($jwks, JWKSetInterface::class, 'The parameter "jwks_uri" must be a valid uri that provide a valid JWKSet.');
                $metadatas['jwks_uri'] = $client_configuration['jwks_uri'];
            }
        } else {
            throw new \InvalidArgumentException('Unsupported token endpoint authentication method.');
        }
    }
}
