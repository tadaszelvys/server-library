<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
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
use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientId;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManager;
use Psr\Http\Message\ServerRequestInterface;

abstract class ClientAssertionJwt implements TokenEndpointAuthMethodInterface
{
    /**
     * @var JWTLoaderInterface
     */
    private $jwtLoader;

    /**
     * @var bool
     */
    private $encryptionRequired = false;

    /**
     * @var \Jose\Object\JWKSetInterface|null
     */
    private $keyEncryptionKeySet = null;

    /**
     * @var int
     */
    private $secretLifetime;

    /**
     * ClientAssertionJwt constructor.
     *
     * @param \Jose\JWTLoaderInterface $jwtLoader
     * @param int                      $secretLifetime
     */
    public function __construct(JWTLoaderInterface $jwtLoader, int $secretLifetime = 0)
    {
        Assertion::greaterOrEqualThan($secretLifetime, 0);
        $this->jwtLoader = $jwtLoader;
        $this->secretLifetime = $secretLifetime;
    }

    /**
     * @param bool                         $encryptionRequired
     * @param \Jose\Object\JWKSetInterface $keyEncryptionKeySet
     */
    public function enableEncryptedAssertions(bool $encryptionRequired, JWKSetInterface $keyEncryptionKeySet)
    {
        $this->encryptionRequired = $encryptionRequired;
        $this->keyEncryptionKeySet = $keyEncryptionKeySet;
    }

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms(): array
    {
        return $this->jwtLoader->getSupportedSignatureAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms(): array
    {
        return $this->jwtLoader->getSupportedContentEncryptionAlgorithms();
    }

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms(): array
    {
        return $this->jwtLoader->getSupportedKeyEncryptionAlgorithms();
    }

    /**
     * {@inheritdoc}
     */
    public function getSchemesParameters(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function findClientId(ServerRequestInterface $request, &$clientCredentials = null)
    {
        $parameters = $request->getParsedBody() ?? [];
        if (!array_key_exists('client_assertion_type', $parameters)) {
            return;
        }
        $clientAssertionType = $parameters['client_assertion_type'];

        //We verify the client assertion type in the request
        if ('urn:ietf:params:oauth:client-assertion-type:jwt-bearer' !== $clientAssertionType) {
            return;
        }

        try {
            Assertion::keyExists($parameters, 'client_assertion', 'Parameter \'client_assertion\' is missing.');
            $client_assertion = $parameters['client_assertion'];
            $jwt = $this->jwtLoader->load($client_assertion, $this->keyEncryptionKeySet, $this->encryptionRequired);

            $diff = array_diff(['iss', 'sub', 'aud', 'jti', 'exp'], array_keys($jwt->getClaims()));
            Assertion::eq(0, count($diff), sprintf('The following claim(s) is/are mandatory: \'%s\'.', implode(', ', array_values($diff))));
            Assertion::eq($jwt->getClaim('sub'), $jwt->getClaim('iss'), 'The claims \'sub\' and \'iss\' must contain the client public ID.');
        } catch (\Exception $e) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManager::ERROR_INVALID_REQUEST,
                    'error_description' => $e->getMessage(),
                ]
            );
        }

        $clientCredentials = $jwt;

        return ClientId::create($jwt->getClaim('sub'));
    }

    /**
     * {@inheritdoc}
     */
    public function isClientAuthenticated(Client $client, $clientCredentials, ServerRequestInterface $request): bool
    {
        $jwk_set = $client->getPublicKeySet();
        if (!$jwk_set instanceof JWKSetInterface) {
            return false;
        }

        try {
            $this->jwtLoader->verify(
                $clientCredentials,
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
    public function getSupportedAuthenticationMethods(): array
    {
        return ['client_secret_jwt', 'private_key_jwt'];
    }

    /**
     * {@inheritdoc}
     */
    public function checkClientConfiguration(array $commandParameters, array &$validatedParameters)
    {
        if ('client_secret_jwt' === $commandParameters['token_endpoint_auth_method']) {
            $validatedParameters['client_secret'] = $this->createClientSecret();
            $validatedParameters['client_secret_expires_at'] = (0 === $this->secretLifetime ? 0 : time() + $this->secretLifetime);
        } elseif ('private_key_jwt' === $commandParameters['token_endpoint_auth_method']) {
            Assertion::true(array_key_exists('jwks', $commandParameters) xor array_key_exists('jwks_uri', $commandParameters), 'The parameter \'jwks\' or \'jwks_uri\' must be set.');
            if (array_key_exists('jwks', $commandParameters)) {
                $jwks = new JWKSet($commandParameters['jwks']);
                Assertion::isInstanceOf($jwks, JWKSetInterface::class, 'The parameter \'jwks\' must be a valid JWKSet object.');
                $validatedParameters['jwks'] = $commandParameters['jwks'];
            } else {
                $jwks = JWKFactory::createFromJKU($commandParameters['jwks_uri']);
                Assertion::isInstanceOf($jwks, JWKSetInterface::class, 'The parameter \'jwks_uri\' must be a valid uri that provide a valid JWKSet.');
                $validatedParameters['jwks_uri'] = $commandParameters['jwks_uri'];
            }
        } else {
            throw new \InvalidArgumentException('Unsupported token endpoint authentication method.');
        }
    }

    /**
     * @return string
     */
    abstract protected function createClientSecret();
}
