<?php

namespace OAuth2\Token;

interface AuthCodeInterface extends TokenInterface
{
    /**
     * @return string The Authorization Code
     */
    public function getCode();

    /**
     * @param string $code
     *
     * @return self
     */
    public function setCode($code);

    /**
     * @return bool A refresh token is asked and authorized by the resource owner and/or the authorization server
     */
    public function getIssueRefreshToken();

    /**
     * @param bool $issue_refresh_token
     *
     * @return self
     */
    public function setIssueRefreshToken($issue_refresh_token);

    /**
     * @return string The redirect URI set in the authorization request
     */
    public function getRedirectUri();

    /**
     * @param string $redirect_uri
     *
     * @return self
     */
    public function setRedirectUri($redirect_uri);
}
