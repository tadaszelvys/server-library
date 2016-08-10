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

use OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface;

trait HasPKCEMethodManager
{
    /**
     * @var \OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface
     */
    private $pkce_method_manager;

    /**
     * @return \OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface
     */
    private function getPKCEMethodManager()
    {
        return $this->pkce_method_manager;
    }

    /**
     * @param \OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface $pkce_method_manager
     */
    private function setPKCEMethodManager(PKCEMethodManagerInterface $pkce_method_manager)
    {
        $this->pkce_method_manager = $pkce_method_manager;
    }
}
