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
use OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface;

trait HasPKCEMethodManager
{
    /**
     * @var \OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface|null
     */
    private $pkce_method_manager = null;

    /**
     * @return bool
     */
    protected function hasPKCEMethodManager()
    {
        return null !== $this->pkce_method_manager;
    }

    /**
     * @return \OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface
     */
    protected function getPKCEMethodManager()
    {
        Assertion::true($this->hasPKCEMethodManager(), 'The PKCE method manager is not available.');

        return $this->pkce_method_manager;
    }

    /**
     * @param \OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface $pkce_method_manager
     */
    protected function setPKCEMethodManager(PKCEMethodManagerInterface $pkce_method_manager)
    {
        $this->pkce_method_manager = $pkce_method_manager;
    }
}
