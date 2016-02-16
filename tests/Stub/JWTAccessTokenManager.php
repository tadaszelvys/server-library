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

use Jose\Object\JWKInterface;
use OAuth2\Token\AccessToken;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\JWTAccessTokenManager as Base;
use OAuth2\Util\JWTCreator;
use OAuth2\Util\JWTLoader;

class JWTAccessTokenManager extends Base
{
    /**
     * @var \OAuth2\Token\AccessTokenInterface[]
     */
    private $access_tokens = [];

    /**
     * JWTAccessTokenManager constructor.
     *
     * @param \OAuth2\Util\JWTCreator   $jwt_creator
     * @param \OAuth2\Util\JWTLoader    $jwt_loader
     * @param string                    $signature_algorithm
     * @param \Jose\Object\JWKInterface $signature_key
     * @param string                    $issuer
     */
    public function __construct(JWTCreator $jwt_creator,
                                JWTLoader $jwt_loader,
                                $signature_algorithm,
                                JWKInterface $signature_key,
                                $issuer
    ) {
        parent::__construct(
            $jwt_creator,
            $jwt_loader,
            $signature_algorithm,
            $signature_key,
            $issuer
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

        $user_info = new AccessToken();
        $user_info->setExpiresAt(time() + 3600);
        $user_info->setResourceOwnerPublicId('user1');
        $user_info->setScope(['openid', 'profile', 'email', 'address', 'phone']);
        $user_info->setClientPublicId('foo');
        $user_info->setToken('USER_INFO');
        $user_info->setTokenType('Bearer');

        $this->access_tokens[$abcd->getToken()] = $abcd;
        $this->access_tokens[$efgh->getToken()] = $efgh;
        $this->access_tokens[$user_info->getToken()] = $user_info;
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
