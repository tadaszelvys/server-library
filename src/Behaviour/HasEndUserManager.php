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

use OAuth2\EndUser\EndUserManagerInterface;

trait HasEndUserManager
{
    /**
     * @var \OAuth2\EndUser\EndUserManagerInterface
     */
    private $end_user_manager;

    /**
     * @return \OAuth2\EndUser\EndUserManagerInterface
     */
    protected function getEndUserManager()
    {
        return $this->end_user_manager;
    }

    /**
     * @param \OAuth2\EndUser\EndUserManagerInterface $end_user_manager
     */
    private function setEndUserManager(EndUserManagerInterface $end_user_manager)
    {
        $this->end_user_manager = $end_user_manager;
    }
}
