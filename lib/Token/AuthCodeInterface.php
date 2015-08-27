<?php

namespace OAuth2\Token;

interface AuthCodeInterface extends TokenInterface
{
    /**
     * @return string The Authorization Code
     */
    public function getCode();

    /**
     * @return bool A refresh token is asked and authorized by the resource owner and/or the authorization server
     */
    public function getIssueRefreshToken();

    /**
     * @return string The redirect URI set in the authorization request
     */
    public function getRedirectUri();
}
