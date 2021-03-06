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
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

class JWTBearerGrantType implements GrantTypeInterface
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
     * @var bool
     */
    private $issue_refresh_token_with_access_token = false;

    /**
     * JWTBearerGrantType constructor.
     *
     * @param \Jose\JWTLoaderInterface                    $loader
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(JWTLoaderInterface $loader, ExceptionManagerInterface $exception_manager)
    {
        $this->setJWTLoader($loader);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedResponseTypes()
    {
        return [];
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
        try {
            Assertion::notNull($assertion, 'Parameter "assertion" is missing.');
            $jwt = $this->getJWTLoader()->load(
                $assertion,
                $this->key_encryption_key_set,
                $this->encryption_required
            );
            Assertion::isInstanceOf($jwt, JWSInterface::class, 'Assertion does not contain signed claims.');
            Assertion::true($jwt->hasClaim('sub'), 'Assertion does not contain "sub" claims.');
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_REQUEST, $e->getMessage());
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
        if (false === $client->hasPublicKeySet()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_CLIENT, 'The client is not a client with signature capabilities.');
        }
        $jwt = $grant_type_response->getAdditionalData('jwt');

        try {
            $this->getJWTLoader()->verify(
                $jwt,
                $client->getPublicKeySet()
            );
        } catch (\Exception $e) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_REQUEST, $e->getMessage());
        }

        $issue_refresh_token = $this->isRefreshTokenIssuedWithAccessToken();

        $grant_type_response->setResourceOwnerPublicId($client->getPublicId());
        $grant_type_response->setUserAccountPublicId(null);
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
