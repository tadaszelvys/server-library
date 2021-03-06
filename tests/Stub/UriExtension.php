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
use OAuth2\Exception\Extension\ExceptionExtensionInterface;

final class UriExtension implements ExceptionExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function process($type, $error, $error_description, array &$data)
    {
        $data['error_uri'] = "https://foo.test/Error/$type/$error";
    }
}
