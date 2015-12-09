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

interface AccessTokenInterface extends TokenInterface, \JsonSerializable
{
    /**
     * The unique token string to identify the Access Token.
     *
     * @return string
     */
    public function getToken();

    /**
     * @param string $token
     *
     * @return self
     */
    public function setToken($token);

    /**
     * The refresh token associated with the access token.
     * Return null if no refresh token is associated.
     *
     * @return string|null
     */
    public function getRefreshToken();

    /**
     * @param string|null $refresh_token
     *
     * @return self
     */
    public function setRefreshToken($refresh_token);
}
