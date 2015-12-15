<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

interface IdTokenInterface extends TokenInterface
{
    /**
     * The unique token string to identify the Access Token.
     *
     * @return string
     */
    public function getToken();

    /**
     * @param string $token
     */
    public function setToken($token);
}
