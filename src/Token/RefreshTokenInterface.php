<?php

namespace OAuth2\Token;

interface RefreshTokenInterface extends TokenInterface
{
    /**
     * Is the refresh token marked as used.
     *
     * @return bool
     */
    public function isUsed();

    /**
     * @param bool $used
     */
    public function setUsed($used);
}
