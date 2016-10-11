<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

use Assert\Assertion;
use OAuth2\Token\AccessTokenManagerInterface;

trait HasAccessTokenManager
{
    /**
     * @var \OAuth2\Token\AccessTokenManagerInterface|null
     */
    private $access_token_manager = null;

    /**
     * @return bool
     */
    protected function hasAccessTokenManager()
    {
        return null !== $this->access_token_manager;
    }

    /**
     * @return \OAuth2\Token\AccessTokenManagerInterface
     */
    protected function getAccessTokenManager()
    {
        Assertion::true($this->hasAccessTokenManager(), 'The access token manager is not available.');

        return $this->access_token_manager;
    }

    /**
     * @param \OAuth2\Token\AccessTokenManagerInterface $access_token_manager
     */
    protected function setAccessTokenManager(AccessTokenManagerInterface $access_token_manager)
    {
        $this->access_token_manager = $access_token_manager;
    }
}
