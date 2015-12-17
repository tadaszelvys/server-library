<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\RevocationTokenType;


use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\TokenInterface;

final class AccessToken implements RevocationTokenTypeInterface
{
    use HasAccessTokenManager;

    /**
     * AccessToken constructor.
     *
     * @param \OAuth2\Token\AccessTokenManagerInterface $access_token_manager
     */
    public function __construct(AccessTokenManagerInterface $access_token_manager)
    {
        $this->setAccessTokenManager($access_token_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeHint()
    {
        return 'access_token';
    }

    /**
     * {@inheritdoc}
     */
    public function getToken($token)
    {
        return $this->getAccessTokenManager()->getAccessToken($token);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeToken(TokenInterface $token)
    {
        if ($token instanceof AccessTokenInterface) {
            $this->getAccessTokenManager()->revokeAccessToken($token);
        }
    }
}
