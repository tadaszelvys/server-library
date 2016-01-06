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

use OAuth2\Client\ClientInterface;
use OAuth2\EndUser\EndUserInterface;

interface AuthCodeManagerInterface
{
    /**
     * Take the provided authorization code values and store them somewhere.
     *
     * This function should be the storage counterpart to getAuthCode().
     * If storage fails for some reason, we're not currently checking for any sort of success/failure, so you should
     * bail out of the script and provide a descriptive fail message.
     *
     * @param \OAuth2\Client\ClientInterface   $client            The client associated with this authorization code.
     * @param \OAuth2\EndUser\EndUserInterface $end_user          End user to associate with this authorization code.
     * @param array                            $query_params      The authorization request query parameters.
     * @param string                           $redirectUri       Redirect URI to be stored.
     * @param string[]                         $scope             (optional) Scopes to be stored.
     * @param bool                             $issueRefreshToken (optional) Issue a refresh token with the access token.
     *
     * @return null|AuthCodeInterface
     */
    public function createAuthCode(ClientInterface $client, EndUserInterface $end_user, array $query_params, $redirectUri, array $scope = [], $issueRefreshToken = false);

    /**
     * Retrieve the stored data for the given authorization code.
     *
     * @param string $code The authorization code string for which to fetch data.
     *
     * @return null|AuthCodeInterface
     *
     * @see     http://tools.ietf.org/html/rfc6749#section-4.1
     */
    public function getAuthCode($code);

    /**
     * Marks auth code as expired.
     *
     * Depending on implementation it can change expiration date on auth code or remove it at all.
     *
     * @param AuthCodeInterface $code
     */
    public function markAuthCodeAsUsed(AuthCodeInterface $code);

    /**
     * @param \OAuth2\Token\TokenUpdaterInterface $token_updater
     */
    public function addTokenUpdater(TokenUpdaterInterface $token_updater);
}
