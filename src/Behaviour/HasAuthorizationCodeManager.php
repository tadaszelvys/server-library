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
use OAuth2\Token\AuthCodeManagerInterface;

trait HasAuthorizationCodeManager
{
    /**
     * @var \OAuth2\Token\AuthCodeManagerInterface|null
     */
    private $authorization_code_manager = null;

    /**
     * @return bool
     */
    protected function hasAuthorizationCodeManager()
    {
        return null !== $this->authorization_code_manager;
    }

    /**
     * @return \OAuth2\Token\AuthCodeManagerInterface
     */
    protected function getAuthorizationCodeManager()
    {
        Assertion::true($this->hasAuthorizationCodeManager(), 'The authorization code manager is not available.');

        return $this->authorization_code_manager;
    }

    /**
     * @param \OAuth2\Token\AuthCodeManagerInterface $authorization_code_manager
     */
    protected function setAuthorizationCodeManager(AuthCodeManagerInterface $authorization_code_manager)
    {
        $this->authorization_code_manager = $authorization_code_manager;
    }
}
