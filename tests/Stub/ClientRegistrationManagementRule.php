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

use Base64Url\Base64Url;
use OAuth2\Client\Rule\ClientRegistrationManagementRule as Base;

class ClientRegistrationManagementRule extends Base
{
    /**
     * {@inheritdoc}
     */
    protected function getRegistrationClientUri(string $clientId)
    {
        return sprintf('https://www.config.example.com/client/%s', $clientId);
    }

    /**
     * {@inheritdoc}
     */
    protected function generateRegistrationAccessToken()
    {
        return Base64Url::encode(random_bytes(64));
    }
}
