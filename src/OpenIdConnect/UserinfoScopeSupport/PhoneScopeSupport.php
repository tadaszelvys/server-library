<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\UserinfoScopeSupport;

final class PhoneScopeSupport implements UserinfoScopeSupportInterface
{
    /**
     * {@inheritdoc}
     */
    public function getScope()
    {
        return 'phone';
    }

    /**
     * {@inheritdoc}
     */
    public function getClaims()
    {
        return [
            'phone_number',
            'phone_number_verified',
        ];
    }
}
