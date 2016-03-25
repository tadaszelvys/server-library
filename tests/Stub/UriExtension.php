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

/**
 */
class UriExtension implements ExceptionExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getData($type, $error, $error_description = null, array $data = [])
    {
        if ($type !== ExceptionManagerInterface::INTERNAL_SERVER_ERROR) {
            return ['error_uri' => urlencode("https://foo.test/Error/$type/$error")];
        }

        return ['error_uri' => urlencode("https://foo.test/Internal/$type/$error")];
    }
}
