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

interface TokenInterface
{
    /**
     * @return string
     */
    public function getToken();

    /**
     * @param string $token
     */
    public function setToken($token);

    /**
     * @return int
     */
    public function getExpiresAt();

    /**
     * @param int $expires_at
     */
    public function setExpiresAt($expires_at);

    /**
     * @return bool true if the token has expired
     */
    public function hasExpired();

    /**
     * @return int Seconds before the token expiration date
     */
    public function getExpiresIn();

    /**
     * The user account associated to the token.
     * This information is available only is the resource owner is a user.
     *
     * @return string|null The public ID of the user account associated with the token
     */
    public function getUserAccountPublicId();

    /**
     * @param string $user_account_public_id
     */
    public function setUserAccountPublicId($user_account_public_id);

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
}
