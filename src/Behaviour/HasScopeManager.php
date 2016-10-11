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
use OAuth2\Scope\ScopeManagerInterface;

trait HasScopeManager
{
    /**
     * @var \OAuth2\Scope\ScopeManagerInterface|null
     */
    private $scope_manager;

    /**
     * @return bool
     */
    protected function hasScopeManager()
    {
        return null !== $this->scope_manager;
    }

    /**
     * @return \OAuth2\Scope\ScopeManagerInterface
     */
    protected function getScopeManager()
    {
        Assertion::true($this->hasScopeManager(), 'The scope manager is not available.');

        return $this->scope_manager;
    }

    /**
     * @param \OAuth2\Scope\ScopeManagerInterface $scope_manager
     */
    protected function setScopeManager(ScopeManagerInterface $scope_manager)
    {
        $this->scope_manager = $scope_manager;
    }
}
