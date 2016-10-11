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
use OAuth2\UserAccount\UserAccountManagerInterface;

trait HasUserAccountManager
{
    /**
     * @var \OAuth2\UserAccount\UserAccountManagerInterface|null
     */
    private $user_account_manager = null;

    /**
     * @return bool
     */
    protected function hasUserAccountManager()
    {
        return null !== $this->user_account_manager;
    }

    /**
     * @return \OAuth2\UserAccount\UserAccountManagerInterface
     */
    protected function getUserAccountManager()
    {
        Assertion::true($this->hasUserAccountManager(), 'The user account manager is not available.');

        return $this->user_account_manager;
    }

    /**
     * @param \OAuth2\UserAccount\UserAccountManagerInterface $user_account_manager
     */
    protected function setUserAccountManager(UserAccountManagerInterface $user_account_manager)
    {
        $this->user_account_manager = $user_account_manager;
    }
}
