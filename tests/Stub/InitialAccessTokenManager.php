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

use OAuth2\Token\InitialAccessToken;
use OAuth2\Token\InitialAccessTokenInterface;
use OAuth2\Token\InitialAccessTokenManager as Base;

class InitialAccessTokenManager extends Base
{
    /**
     * @var \OAuth2\Token\AccessTokenInterface[]
     */
    private $initial_access_tokens = [];

    /**
     * InitialAccessTokenManager constructor.
     */
    public function __construct()
    {
        $valid_initial_access_token = new InitialAccessToken();
        $valid_initial_access_token->setExpiresAt(time() + 3600);
        $valid_initial_access_token->setUserAccountPublicId('user1');
        $valid_initial_access_token->setToken('INITIAL_ACCESS_TOKEN_VALID');
        $valid_initial_access_token->setParameter('token_type', 'Bearer');
        $this->saveInitialAccessToken($valid_initial_access_token);

        $expired_initial_access_token = new InitialAccessToken();
        $expired_initial_access_token->setExpiresAt(time() - 3600);
        $expired_initial_access_token->setUserAccountPublicId('user1');
        $expired_initial_access_token->setToken('INITIAL_ACCESS_TOKEN_EXPIRED');
        $expired_initial_access_token->setParameter('token_type', 'Bearer');
        $this->saveInitialAccessToken($expired_initial_access_token);
    }

    /**
     * {@inheritdoc}
     */
    public function saveInitialAccessToken(InitialAccessTokenInterface $initial_access_token)
    {
        $this->initial_access_tokens[$initial_access_token->getToken()] = $initial_access_token;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeInitialAccessToken(InitialAccessTokenInterface $initial_access_token)
    {
        if (isset($this->initial_access_tokens[$initial_access_token->getToken()])) {
            unset($this->initial_access_tokens[$initial_access_token->getToken()]);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getInitialAccessToken($initial_access_token)
    {
        return array_key_exists($initial_access_token, $this->initial_access_tokens) ? $this->initial_access_tokens[$initial_access_token] : null;
    }
}
