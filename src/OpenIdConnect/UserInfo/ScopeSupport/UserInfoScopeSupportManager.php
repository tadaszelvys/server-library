<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\UserInfo\ScopeSupport;

use Assert\Assertion;

class UserInfoScopeSupportManager implements UserInfoScopeSupportManagerInterface
{
    /**
     * @var \OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportInterface[]
     */
    private $userinfo_scope_supports = [];

    /**
     * {@inheritdoc}
     */
    public function addUserInfoScopeSupport(UserInfoScopeSupportInterface $userinfo_scope_support)
    {
        $this->userinfo_scope_supports[$userinfo_scope_support->getScope()] = $userinfo_scope_support;
    }

    /**
     * {@inheritdoc}
     */
    public function hasUserInfoScopeSupport($scope)
    {
        return array_key_exists($scope, $this->userinfo_scope_supports);
    }

    /**
     * {@inheritdoc}
     */
    public function getUserInfoScopeSupport($scope)
    {
        Assertion::true($this->hasUserInfoScopeSupport($scope), sprintf('The userinfo scope "%s" is not supported.', $scope));

        return $this->userinfo_scope_supports[$scope];
    }
}
