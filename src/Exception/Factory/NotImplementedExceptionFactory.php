<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Exception\Factory;

use OAuth2\Exception\NotImplementedException;

final class NotImplementedExceptionFactory implements ExceptionFactoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return 'NotImplemented';
    }

    /**
     * {@inheritdoc}
     */
    public function createException($error, $error_description, array $error_data, array $data)
    {
        return new NotImplementedException($error, $error_description, $error_data, $data);
    }
}
