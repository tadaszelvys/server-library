<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\UserInfo\ScopeSupport;

use Assert\Assertion;

class UserInfoScopeSupportManager implements UserInfoScopeSupportManagerInterface
{
    /**
     * @var UserInfoScopeSupportInterface[]
     */
    private $userinfoScopeSupports = [];

    /**
     * {@inheritdoc}
     */
    public function addUserInfoScopeSupport(UserInfoScopeSupportInterface $userinfoScopeSupport): UserInfoScopeSupportManagerInterface
    {
        $this->userinfoScopeSupports[$userinfoScopeSupport->getScope()] = $userinfoScopeSupport;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function hasUserInfoScopeSupport($scope): bool
    {
        return array_key_exists($scope, $this->userinfoScopeSupports);
    }

    /**
     * {@inheritdoc}
     */
    public function getUserInfoScopeSupport($scope): UserInfoScopeSupportInterface
    {
        Assertion::true($this->hasUserInfoScopeSupport($scope), sprintf('The userinfo scope \'%s\' is not supported.', $scope));

        return $this->userinfoScopeSupports[$scope];
    }
}
