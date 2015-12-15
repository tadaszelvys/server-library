<?php

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
