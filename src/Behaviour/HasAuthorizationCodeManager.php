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

use OAuth2\Token\AuthCodeManagerInterface;

trait HasAuthorizationCodeManager
{
    /**
     * @var \OAuth2\Token\AuthCodeManagerInterface
     */
    private $authorization_code_manager;

    /**
     * @return \OAuth2\Token\AuthCodeManagerInterface
     */
    private function getAuthorizationCodeManager()
    {
        return $this->authorization_code_manager;
    }

    /**
     * @param \OAuth2\Token\AuthCodeManagerInterface $authorization_code_manager
     */
    private function setAuthorizationCodeManager(AuthCodeManagerInterface $authorization_code_manager)
    {
        $this->authorization_code_manager = $authorization_code_manager;
    }
}
