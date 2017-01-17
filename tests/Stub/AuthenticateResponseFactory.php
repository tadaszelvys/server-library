<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Response\Factory\AuthenticateResponseFactory as Base;

class AuthenticateResponseFactory extends Base
{
    protected function getSchemes(): array
    {
        return ['Bearer realm="My service"', 'MAC'];
    }
}
