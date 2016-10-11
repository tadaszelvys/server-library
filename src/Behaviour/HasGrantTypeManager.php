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
use OAuth2\Grant\GrantTypeManagerInterface;

trait HasGrantTypeManager
{
    /**
     * @var \OAuth2\Grant\GrantTypeManagerInterface|null
     */
    private $grant_type_manager = null;

    /**
     * @return bool
     */
    protected function hasGrantTypeManager()
    {
        return null !== $this->grant_type_manager;
    }

    /**
     * @return \OAuth2\Grant\GrantTypeManagerInterface
     */
    protected function getGrantTypeManager()
    {
        Assertion::true($this->hasGrantTypeManager(), 'The grant type manager is not available.');

        return $this->grant_type_manager;
    }

    /**
     * @param \OAuth2\Grant\GrantTypeManagerInterface $grant_type_manager
     */
    protected function setGrantTypeManager(GrantTypeManagerInterface $grant_type_manager)
    {
        $this->grant_type_manager = $grant_type_manager;
    }
}
