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

use OAuth2\User\UserManagerInterface;

trait HasUserManager
{
    /**
     * @var \OAuth2\User\UserManagerInterface
     */
    private $user_manager;

    /**
     * @return \OAuth2\User\UserManagerInterface
     */
    protected function getUserManager()
    {
        return $this->user_manager;
    }

    /**
     * @param \OAuth2\User\UserManagerInterface $user_manager
     */
    private function setUserManager(UserManagerInterface $user_manager)
    {
        $this->user_manager = $user_manager;
    }
}
