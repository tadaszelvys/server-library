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

use OAuth2\Exception\BaseException;

class TooManyRequestsException extends BaseException
{
    /**
     * {@inheritdoc}
     */
    public function __construct($error, $error_description, array $error_data, array $data)
    {
        parent::__construct(429, $error, $error_description, $error_data, $data);
    }
}
