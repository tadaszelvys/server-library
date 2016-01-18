<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\AccessToken;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\JWTAccessTokenManager as Base;
use OAuth2\Util\JWTEncrypter;
use OAuth2\Util\JWTLoader;
use OAuth2\Util\JWTSigner;

class JWTAccessTokenManager extends Base
{
    /**
     * @var \OAuth2\Token\AccessTokenInterface[]
     */
    private $access_tokens = [];

    /**
     * JWTAccessTokenManager constructor.
     *
     * @param \OAuth2\Util\JWTLoader                       $jwt_loader
     * @param \OAuth2\Util\JWTSigner                       $jwt_signer
     * @param \OAuth2\Util\JWTEncrypter                    $jwt_encrypter
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    public function __construct(
        JWTLoader $jwt_loader,
        JWTSigner $jwt_signer,
        JWTEncrypter $jwt_encrypter,
        ExceptionManagerInterface $exception_manager,
        ConfigurationInterface $configuration
    ) {
        parent::__construct(
            $jwt_loader,
            $jwt_signer,
            $jwt_encrypter,
            $exception_manager,
            $configuration
        );

        $abcd = new AccessToken();
        $abcd->setExpiresAt(time() + 3600);
        $abcd->setResourceOwnerPublicId('bar');
        $abcd->setScope([]);
        $abcd->setClientPublicId('bar');
        $abcd->setRefreshToken(null);
        $abcd->setToken('ABCD');
        $abcd->setTokenType('Bearer');

        $efgh = new AccessToken();
        $efgh->setExpiresAt(time() + 3600);
        $efgh->setResourceOwnerPublicId('foo');
        $efgh->setScope([]);
        $efgh->setClientPublicId('foo');
        $efgh->setRefreshToken('REFRESH_EFGH');
        $efgh->setToken('EFGH');
        $efgh->setTokenType('Bearer');

        $this->access_tokens[$abcd->getToken()] = $abcd;
        $this->access_tokens[$efgh->getToken()] = $efgh;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken(AccessTokenInterface $access_token)
    {
        if (isset($this->access_tokens[$access_token->getToken()])) {
            unset($this->access_tokens[$access_token->getToken()]);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($token)
    {
        return array_key_exists($token, $this->access_tokens) ? $this->access_tokens[$token] : parent::getAccessToken($token);
    }
}
