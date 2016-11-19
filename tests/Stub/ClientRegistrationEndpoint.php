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

use OAuth2\Endpoint\ClientRegistration\ClientRegistrationEndpoint as Base;
use OAuth2\Token\AccessTokenInterface;

final class ClientRegistrationEndpoint extends Base
{
    /**
     * {@inheritdoc}
     */
    protected function isAccessTokenForClientRegistration(AccessTokenInterface $access_token)
    {
        return $access_token->hasScope('urn:oauth:v2:client:registration');
    }
}
