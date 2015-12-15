<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint;

interface TokenIntrospectionEndpointextensionInterface
{
    /**
     * @param \OAuth2\Token\AccessTokenInterface|\OAuth2\Token\RefreshTokenInterface $token
     *
     * @return array
     */
    public function getTokenInformation($token);
}
