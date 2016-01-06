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

interface AccessTokenInterface extends TokenInterface, \JsonSerializable
{
    /**
     * The token type (bearer, mac...).
     *
     * @return string
     */
    public function getTokenType();

    /**
     * @param string $token_type
     */
    public function setTokenType($token_type);

    /**
     * Other parameters.
     *
     * @return array
     */
    public function getParameters();

    /**
     * @param string $key
     *
     * @throws \InvalidArgumentException
     *
     * @return mixed
     */
    public function getParameter($key);

    /**
     * @param string $key
     *
     * @return bool
     */
    public function hasParameter($key);

    /**
     * @param array $parameters
     */
    public function setParameters(array $parameters);

    /**
     * @param string $key
     * @param mixed  $value
     */
    public function setParameter($key, $value);

    /**
     * @param string $key
     */
    public function unsetParameter($key);

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
