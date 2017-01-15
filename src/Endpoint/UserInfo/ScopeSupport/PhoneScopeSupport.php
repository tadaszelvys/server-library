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

class PhoneScopeSupport implements UserInfoScopeSupportInterface
{
    /**
     * {@inheritdoc}
     */
    public function getScope(): string
    {
        return 'phone';
    }

    /**
     * {@inheritdoc}
     */
    public function getClaims(): array
    {
        return [
            'phone_number',
            'phone_number_verified',
        ];
    }
}
