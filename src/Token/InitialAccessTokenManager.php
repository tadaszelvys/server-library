<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use Assert\Assertion;
use OAuth2\UserAccount\UserAccountInterface;

abstract class InitialAccessTokenManager implements InitialAccessTokenManagerInterface
{
    /**
     * @var int
     */
    private $initial_access_token_lifetime = 3600;

    /**
     * @return \OAuth2\Token\InitialAccessTokenInterface
     */
    protected function createEmptyInitialAccessToken()
    {
        return new InitialAccessToken();
    }

    /**
     * {@inheritdoc}
     */
    public function createInitialAccessToken(UserAccountInterface $resource_owner, array $token_type_parameters)
    {
        $initial_access_token = $this->createEmptyInitialAccessToken();
        $initial_access_token->setExpiresAt($this->getInitialAccessTokenLifetime());
        $initial_access_token->setUserAccountPublicId($resource_owner->getPublicId());

        foreach ($token_type_parameters as $key => $value) {
            $initial_access_token->setParameter($key, $value);
        }

        $this->saveInitialAccessToken($initial_access_token);

        return $initial_access_token;
    }

    /**
     * {@inheritdoc}
     */
    public function isInitialAccessTokenValid(InitialAccessTokenInterface $initial_access_token)
    {
        return !$initial_access_token->hasExpired();
    }

    /**
     * @return int
     */
    public function getInitialAccessTokenLifetime()
    {
        return $this->initial_access_token_lifetime;
    }

    /**
     * @param int $initial_access_token_lifetime
     */
    public function setInitialAccessTokenLifetime($initial_access_token_lifetime)
    {
        Assertion::integer($initial_access_token_lifetime);
        Assertion::greaterThan($initial_access_token_lifetime, 0);
        $this->initial_access_token_lifetime = $initial_access_token_lifetime;
    }
}
