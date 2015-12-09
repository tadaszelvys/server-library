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

use OAuth2\Exception\ExceptionManager as Base;

class ExceptionManager extends Base
{
    public function getUri($type, $error, $error_description = null, array $data = [])
    {
        if ($type !== self::INTERNAL_SERVER_ERROR) {
            return "https://foo.test/Error/$type/$error";
        }

        return "https://foo.test/Internal/$type/$error";
    }
}
