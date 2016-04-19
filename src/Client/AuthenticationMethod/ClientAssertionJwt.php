<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client\AuthenticationMethod;

use Assert\Assertion;
use Jose\Object\JWKSetInterface;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use Jose\JWTLoader;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

class ClientAssertionJwt implements AuthenticationMethodInterface
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
     * @var string[]
     */
    private $allowed_key_encryption_algorithms = [];

    /**
     * @var string[]
     */
    private $allowed_content_encryption_algorithms = [];

    /**
     * PasswordClientManager constructor.
     *
     * @param \Jose\JWTLoader                      $jwt_loader
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(JWTLoader $jwt_loader, ExceptionManagerInterface $exception_manager)
    {
        $this->setJWTLoader($jwt_loader);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @param bool                         $encryption_required
     * @param string[]                     $allowed_key_encryption_algorithms
     * @param string[]                     $allowed_content_encryption_algorithms
     * @param \Jose\Object\JWKSetInterface $key_encryption_key_set
     */
    public function enableEncryptedAssertions($encryption_required,
                                              array $allowed_key_encryption_algorithms,
                                              array $allowed_content_encryption_algorithms,
                                              JWKSetInterface $key_encryption_key_set)
    {
        Assertion::boolean($encryption_required);
        Assertion::notEmpty($allowed_key_encryption_algorithms);
        Assertion::notEmpty($allowed_content_encryption_algorithms);

        $this->encryption_required = $encryption_required;
        $this->allowed_key_encryption_algorithms = $allowed_key_encryption_algorithms;
        $this->allowed_content_encryption_algorithms = $allowed_content_encryption_algorithms;
        $this->key_encryption_key_set = $key_encryption_key_set;
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
        //We verify the client assertion exists
        if (null === $client_assertion) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "client_assertion" is missing.');
        }

        //We load the assertion
        try {
            $jwt = $this->getJWTLoader()->load(
                $client_assertion,
                $this->allowed_key_encryption_algorithms,
                $this->allowed_content_encryption_algorithms,
                $this->key_encryption_key_set,
                $this->encryption_required
            );
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }

        foreach (['iss', 'sub', 'aud', 'jti', 'exp'] as $claim) {
            if (false === $jwt->hasClaim($claim)) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, sprintf('The claim "%s" is mandatory.', $claim));
            }
        }

        if ($jwt->getClaim('sub') !== $jwt->getClaim('iss')) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The claims "sub" and "iss" must contain the client public ID.');
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
            $this->getJWTLoader()->verifySignature(
                $client_credentials,
                $jwk_set,
                $this->getJWTLoader()->getSupportedSignatureAlgorithms()
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
}
