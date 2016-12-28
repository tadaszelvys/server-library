<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\InitialAccessToken;

use OAuth2\Model\UserAccount\UserAccount;

interface InitialAccessTokenRepositoryInterface
{
    /**
     * @param UserAccount             $userAccount
     * @param \DateTimeImmutable|null $expiresAt
     *
     * @return InitialAccessToken
     */
    public function create(UserAccount $userAccount, \DateTimeImmutable $expiresAt = null);

    /**
     * @param InitialAccessToken $initialAccessToken
     */
    public function save(InitialAccessToken $initialAccessToken);

    /**
     * This function revoke an initial access token.
     *
     * @param InitialAccessToken $initialAccessToken The initial access token to revoke
     */
    public function revoke(InitialAccessToken $initialAccessToken);

    /**
     * This function verifies the request and validate or not the initial access token.
     * MUST return null if the initial access token is not valid (expired, revoked...).
     *
     * @param InitialAccessTokenId $initialAccessTokenId The initial access token
     *
     * @return InitialAccessToken|null Return the initial access token or null if the argument is not a valid initial access token
     */
    public function find(InitialAccessTokenId $initialAccessTokenId);
}
