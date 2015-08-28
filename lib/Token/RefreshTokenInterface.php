<?php

namespace OAuth2\Token;

interface RefreshTokenInterface extends TokenInterface
{
    /**
     * The unique token string to identify the Refresh Token.
     *
     * @return string
     */
    public function getToken();

    /**
     * Is the refresh token marked as used.
     *
     * @return bool
     */
    public function isUsed();
}
