<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\UserInfo;

use OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportManagerInterface;

trait HasUserInfoScopeSupportManager
{
    /**
     * @var \OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportManagerInterface
     */
    private $userinfo_scope_support_manager;

    /**
     * @param \OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportManagerInterface $userinfo_scope_support_manager
     */
    public function setUserInfoScopeSupportManager(UserInfoScopeSupportManagerInterface $userinfo_scope_support_manager)
    {
        $this->userinfo_scope_support_manager = $userinfo_scope_support_manager;
    }

    /**
     * @return \OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportManagerInterface
     */
    public function getUserInfoScopeSupportManager()
    {
        return $this->userinfo_scope_support_manager;
    }
}
