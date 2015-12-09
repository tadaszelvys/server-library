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

interface AuthCodeInterface extends TokenInterface
{
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

    /**
     * @return array The parameters from the authorization request
     */
    public function getQueryParams();

    /**
     * @param array $query_params
     *
     * @return self
     */
    public function setQueryParams(array $query_params);
}
