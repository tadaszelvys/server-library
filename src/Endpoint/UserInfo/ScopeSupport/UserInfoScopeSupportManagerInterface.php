<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\UserInfo\ScopeSupport;

interface UserInfoScopeSupportManagerInterface
{
    /**
     * @param UserInfoScopeSupportInterface $userinfoScopeSupport
     * @return UserInfoScopeSupportManagerInterface
     */
    public function addUserInfoScopeSupport(UserInfoScopeSupportInterface $userinfoScopeSupport): self;

    /**
     * @param string $scope
     *
     * @return bool
     */
    public function hasUserInfoScopeSupport($scope): bool;

    /**
     * @param string $scope
     *
     * @throws \InvalidArgumentException
     *
     * @return UserinfoScopeSupportInterface
     */
    public function getUserInfoScopeSupport($scope): UserinfoScopeSupportInterface;
}
