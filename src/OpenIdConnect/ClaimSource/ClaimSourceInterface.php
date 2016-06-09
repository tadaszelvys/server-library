<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\ClaimSource;

use OAuth2\User\UserInterface;

interface ClaimSourceInterface
{
    /**
     * @param \OAuth2\User\UserInterface $user
     * @param string[]                   $scope
     * @param array                      $claims
     *
     * @return \OAuth2\OpenIdConnect\ClaimSource\SourceInterface|null
     */
    public function getUserInfo(UserInterface $user, array $scope, array $claims);
}
