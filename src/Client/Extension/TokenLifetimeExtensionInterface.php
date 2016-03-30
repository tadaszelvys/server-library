<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client\Extension;

/**
 * This extension will help client to override token lifetime configuration defined by the server.
 */
interface TokenLifetimeExtensionInterface
{
    /**
     * @param string $token Type of token (e.g. authcode, access_token, refresh_token or any other custom token type)
     *
     * @return null|int Returns null if no lifetime has been set for the token type, else an integer that repnesents the lifetime in seconds.
     */
    public function getTokenLifetime($token);
}
