<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\OpenIdConnect\ClaimSource\ClaimSourceInterface;
use OAuth2\OpenIdConnect\ClaimSource\Source;
use OAuth2\UserAccount\UserAccountInterface;

class DistributedClaimSource implements ClaimSourceInterface
{
    /**
     * {@inheritdoc}
     */
    public function getUserInfo(UserAccountInterface $user_account, array $scope, array $claims)
    {
        if ('user2' === $user_account->getPublicId()) {
            $claims = ['address', 'email', 'email_verified'];
            $source = [
                'endpoint'     => 'https://external.service.local/user/info',
                'access_token' => '0123456789',
                'token_type'   => 'Bearer',
            ];

            return new Source($claims, $source);
        }
    }
}
