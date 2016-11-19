<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

interface AccessTokenInterface extends OAuth2TokenInterface, \JsonSerializable
{
    /**
     * The token type (bearer, mac...).
     *
     * @return string
     */
    public function getTokenType();

    /**
     * The refresh token associated with the access token.
     * Return null if no refresh token is associated.
     *
     * @return string|null
     */
    public function getRefreshToken();

    /**
     * @param string|null $refresh_token
     */
    public function setRefreshToken($refresh_token);

    /**
     * @return array
     */
    public function toArray();
}
