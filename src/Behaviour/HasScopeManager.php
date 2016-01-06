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

use OAuth2\Scope\ScopeManagerInterface;

trait HasScopeManager
{
    /**
     * @var \OAuth2\Scope\ScopeManagerInterface
     */
    private $scope_manager;

    /**
     * {@inheritdoc}
     */
    protected function getScopeManager()
    {
        return $this->scope_manager;
    }

    /**
     * @param \OAuth2\Scope\ScopeManagerInterface $scope_manager
     */
    private function setScopeManager(ScopeManagerInterface $scope_manager)
    {
        $this->scope_manager = $scope_manager;
    }
}
