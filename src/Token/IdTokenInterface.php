<?php

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
