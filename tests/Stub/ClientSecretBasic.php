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
use OAuth2\TokenEndpointAuthMethod\ClientSecretBasic as Base;


class ClientSecretBasic extends Base
{
    /**
     * {@inheritdoc}
     */
    protected function createClientSecret()
    {
        return Base64Url::encode(random_bytes(64));
    }
}
