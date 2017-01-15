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
use OAuth2\Endpoint\Token\GrantTypeData;
use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class JWTBearerGrantType implements GrantTypeInterface
{
    /**
     * @var bool
     */
    private $encryptionRequired = false;

    /**
     * @var JWKSetInterface|null
     */
    private $keyEncryptionkeySet = null;

    /**
     * @var bool
     */
    private $issueRefreshToken = false;

    /**
     * JWTBearerGrantType constructor.
     *
     * @param \Jose\JWTLoaderInterface                               $loader
     * @param \OAuth2\Response\OAuth2ResponseFactoryManagerInterface $response_factory_manager
     */
    public function __construct(JWTLoaderInterface $loader, OAuth2ResponseFactoryManagerInterface $response_factory_manager)
    {
        $this->setJWTLoader($loader);
        $this->setResponsefactoryManager($response_factory_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedResponseTypes(): array
    {
        return [];
    }

    /**
     * @param bool            $encryptionRequired
     * @param JWKSetInterface $keyEncryptionkeySet
     */
    public function enableEncryptedAssertions($encryptionRequired,
                                              JWKSetInterface $keyEncryptionkeySet)
    {
        Assertion::boolean($encryptionRequired);

        $this->encryptionRequired = $encryptionRequired;
        $this->keyEncryptionkeySet = $keyEncryptionkeySet;
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType(): string
    {
        return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    }

    /**
     * {@inheritdoc}
     */
    public function prepareTokenResponse(ServerRequestInterface $request, GrantTypeData &$grantTypeResponse)
    {
        $assertion = RequestBody::getParameter($request, 'assertion');
        try {
            Assertion::notNull($assertion, 'Parameter \'assertion\' is missing.');
            $jwt = $this->getJWTLoader()->load(
                $assertion,
                $this->keyEncryptionkeySet,
                $this->encryptionRequired
            );
            Assertion::isInstanceOf($jwt, JWSInterface::class, 'Assertion does not contain signed claims.');
            Assertion::true($jwt->hasClaim('sub'), 'Assertion does not contain \'sub\' claims.');
        } catch (\Exception $e) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => $e->getMessage(),
                ]
            );
        }

        //We modify the response:
        // - We add the subject as the client public id
        // - We transmit the JWT to the response for further needs
        $grantTypeResponse->setClientPublicId($jwt->getClaim('sub'));
        $grantTypeResponse->setAdditionalData('jwt', $jwt);
    }

    /**
     * {@inheritdoc}
     */
    public function grant(ServerRequestInterface $request, Client $client, GrantTypeData &$grantTypeResponse)
    {
        if (false === $client->hasPublicKeySet()) {
            throw new OAuth2Exception(400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT,
                    'error_description' => 'The client is not a client with signature capabilities.',
                ]
            );
        }
        $jwt = $grantTypeResponse->getAdditionalData('jwt');

        try {
            $this->getJWTLoader()->verify(
                $jwt,
                $client->getPublicKeySet()
            );
        } catch (\Exception $e) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => $e->getMessage(),
                ]
            );
        }

        $issueRefreshToken = $this->isRefreshTokenIssuedWithAccessToken();

        $grantTypeResponse->setResourceOwnerPublicId($client->getId()->getValue());
        $grantTypeResponse->setUserAccountPublicId(null);
        $grantTypeResponse->setRefreshTokenIssued($issueRefreshToken);
        $grantTypeResponse->setRefreshTokenScope($grantTypeResponse->getRequestedScope());
    }

    /**
     * @return bool
     */
    public function isRefreshTokenIssuedWithAccessToken(): bool
    {
        return $this->issueRefreshToken;
    }

    public function enableRefreshTokenIssuanceWithAccessToken()
    {
        $this->issueRefreshToken = true;
    }

    public function disableRefreshTokenIssuanceWithAccessToken()
    {
        $this->issueRefreshToken = false;
    }
}
