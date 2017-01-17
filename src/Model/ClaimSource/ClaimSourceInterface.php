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

namespace OAuth2\Model\ClaimSource;

use OAuth2\Model\UserAccount\UserAccount;

interface ClaimSourceInterface
{
    /**
     * @param UserAccount $userAccount
     * @param string[]    $scope
     * @param array       $claims
     *
     * @return SourceInterface
     */
    public function getUserInfo(UserAccount $userAccount, array $scope, array $claims);
}
