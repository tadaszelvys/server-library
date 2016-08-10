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

use OAuth2\UserAccount\UserAccountManagerInterface;

trait HasUserAccountManager
{
    /**
     * @var \OAuth2\UserAccount\UserAccountManagerInterface
     */
    private $user_account_manager;

    /**
     * @return \OAuth2\UserAccount\UserAccountManagerInterface
     */
    private function getUserAccountManager()
    {
        return $this->user_account_manager;
    }

    /**
     * @param \OAuth2\UserAccount\UserAccountManagerInterface $user_account_manager
     */
    private function setUserAccountManager(UserAccountManagerInterface $user_account_manager)
    {
        $this->user_account_manager = $user_account_manager;
    }
}
