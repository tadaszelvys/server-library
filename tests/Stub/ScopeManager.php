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

use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Scope\ScopeManager as Base;

class ScopeManager extends Base
{
    /**
     * ClientCredentialsGrantType constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        parent::__construct(
            $exception_manager,
            ['scope1', 'scope2', 'scope3', 'scope4', 'openid', 'profile', 'email', 'phone', 'address', 'offline_access']
        );
    }
}
