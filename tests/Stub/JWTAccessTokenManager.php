<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Token\AccessToken;
use OAuth2\Token\JWTAccessTokenManager as Base;

class JWTAccessTokenManager extends Base
{
    /**
     * {@inheritdoc}
     */
    protected function getClass()
    {
        return new AccessToken();
    }
}
