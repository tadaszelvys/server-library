<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use Assert\Assertion;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\SignatureCapabilitiesInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\JWTLoader;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

final class JWTBearerGrantType implements GrantTypeSupportInterface
{
    use HasExceptionManager;
    use HasJWTLoader;

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
     * @var bool
     */
    private $issue_refresh_token_with_access_token = false;

    /**
     * JWTBearerGrantType constructor.
     *
     * @param \OAuth2\Util\JWTLoader                      $loader
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(
        JWTLoader $loader,
        ExceptionManagerInterface $exception_manager
    ) {
        $this->setJWTLoader($loader);
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
        Assertion::true(empty(array_diff($allowed_key_encryption_algorithms, $this->getJWTLoader()->getSupportedKeyEncryptionAlgorithms())));
        Assertion::true(empty(array_diff($allowed_content_encryption_algorithms, $this->getJWTLoader()->getSupportedContentEncryptionAlgorithms())));

        $this->encryption_required = $encryption_required;
        $this->allowed_key_encryption_algorithms = $allowed_key_encryption_algorithms;
        $this->allowed_content_encryption_algorithms = $allowed_content_encryption_algorithms;
        $this->key_encryption_key_set = $key_encryption_key_set;
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType()
    {
        return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    }

    /**
     * {@inheritdoc}
     */
    public function prepareGrantTypeResponse(ServerRequestInterface $request, GrantTypeResponseInterface &$grant_type_response)
    {
        $assertion = RequestBody::getParameter($request, 'assertion');
        if (null === $assertion) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "assertion" is missing.');
        }

        try {
            $jwt = $this->getJWTLoader()->load(
                $assertion,
                $this->allowed_key_encryption_algorithms,
                $this->allowed_content_encryption_algorithms,
                $this->key_encryption_key_set,
                $this->encryption_required
            );
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }

        if (!$jwt instanceof JWSInterface) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Assertion does not contain signed claims.');
        }

        if (!$jwt->hasClaim('sub')) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Assertion does not contain "sub" claims.');
        }

        //We modify the response:
        // - We add the subject as the client public id
        // - We transmit the JWT to the response for further needs
        $grant_type_response->setClientPublicId($jwt->getClaim('sub'));
        $grant_type_response->setAdditionalData('jwt', $jwt);
    }

    /**
     * {@inheritdoc}
     */
    public function grantAccessToken(ServerRequestInterface $request, ClientInterface $client, GrantTypeResponseInterface &$grant_type_response)
    {
        if (!$client instanceof SignatureCapabilitiesInterface) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_CLIENT, 'The client is not a JWT client');
        }
        $jwt = $grant_type_response->getAdditionalData('jwt');

        $this->getJWTLoader()->verifySignature(
            $jwt,
            $client->getSignaturePublicKeySet(),
            $client->getAllowedSignatureAlgorithms()
        );

        $issue_refresh_token = $this->isRefreshTokenIssuedWithAccessToken();

        $grant_type_response->setResourceOwnerPublicId($client->getPublicId());
        $grant_type_response->setRefreshTokenIssued($issue_refresh_token);
        $grant_type_response->setRefreshTokenScope($grant_type_response->getRequestedScope());
    }

    /**
     * @return bool
     */
    public function isRefreshTokenIssuedWithAccessToken()
    {
        return $this->issue_refresh_token_with_access_token;
    }

    public function enableRefreshTokenIssuanceWithAccessToken()
    {
        $this->issue_refresh_token_with_access_token = true;
    }

    public function disableRefreshTokenIssuanceWithAccessToken()
    {
        $this->issue_refresh_token_with_access_token = false;
    }
}
