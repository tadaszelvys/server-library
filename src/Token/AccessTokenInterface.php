<?php

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
}
