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
use OAuth2\Token\RefreshTokenManagerInterface;

trait HasRefreshTokenManager
{
    /**
     * @var \OAuth2\Token\RefreshTokenManagerInterface|null
     */
    private $refresh_token_manager = null;

    /**
     * @return bool
     */
    protected function hasRefreshTokenManager()
    {
        return null !== $this->refresh_token_manager;
    }

    /**
     * @return \OAuth2\Token\RefreshTokenManagerInterface|null
     */
    protected function getRefreshTokenManager()
    {
        Assertion::true($this->hasRefreshTokenManager(), 'The refresh token manager is not available.');

        return $this->refresh_token_manager;
    }

    /**
     * @param \OAuth2\Token\RefreshTokenManagerInterface $refresh_token_manager
     */
    protected function setRefreshTokenManager(RefreshTokenManagerInterface $refresh_token_manager)
    {
        $this->refresh_token_manager = $refresh_token_manager;
    }
}
