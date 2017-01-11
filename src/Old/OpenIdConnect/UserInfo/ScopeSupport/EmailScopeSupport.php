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

class EmailScopeSupport implements UserInfoScopeSupportInterface
{
    /**
     * {@inheritdoc}
     */
    public function getScope(): string
    {
        return 'email';
    }

    /**
     * {@inheritdoc}
     */
    public function getClaims(): array
    {
        return [
            'email',
            'email_verified',
        ];
    }
}
