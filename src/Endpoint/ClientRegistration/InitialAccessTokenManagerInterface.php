<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\ClientRegistration;

use OAuth2\UserAccount\UserAccountInterface;

interface InitialAccessTokenManagerInterface
{
    /**
     * Creates an initial access token and stores it if necessary.
     *
     * @param \OAuth2\UserAccount\UserAccountInterface $owner                 Resource owner associated with the initial access token.
     * @param array                                    $token_type_parameters The parameters from token type to add to the initial access token
     *
     * @return \OAuth2\Endpoint\ClientRegistration\InitialAccessTokenInterface
     */
    public function createInitialAccessToken(UserAccountInterface $owner, array $token_type_parameters);

    /**
     * @param \OAuth2\Endpoint\ClientRegistration\InitialAccessTokenInterface $initial_access_token
     */
    public function saveInitialAccessToken(InitialAccessTokenInterface $initial_access_token);

    /**
     * This function revoke an initial access token.
     *
     * @param \OAuth2\Endpoint\ClientRegistration\InitialAccessTokenInterface $token The initial access token to revoke
     */
    public function revokeInitialAccessToken(InitialAccessTokenInterface $token);

    /**
     * This function verifies the request and validate or not the initial access token.
     * MUST return null if the initial access token is not valid (expired, revoked...).
     *
     * @param string $initial_access_token The initial access token
     *
     * @return \OAuth2\Endpoint\ClientRegistration\InitialAccessTokenInterface|null Return the initial access token or null if the argument is not a valid initial access token
     */
    public function getInitialAccessToken($initial_access_token);

    /**
     * @param \OAuth2\Endpoint\ClientRegistration\InitialAccessTokenInterface $token
     *
     * @return bool True if the initial access token is valid, else false
     */
    public function isInitialAccessTokenValid(InitialAccessTokenInterface $token);
}
