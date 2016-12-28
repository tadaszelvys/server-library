<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\AuthCode;

use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;

interface AuthCodeRepositoryInterface
{
    /**
     * @param Client             $client
     * @param UserAccount        $userAccount
     * @param array              $queryParameters
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $scopes
     * @param array              $metadatas
     *
     * @return mixed
     */
    public function create(Client $client, UserAccount $userAccount, array $queryParameters, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas);

    /**
     * @param AuthCode $authCode
     */
    public function save(AuthCode $authCode);

    /**
     * Retrieve the stored data for the given authorization code.
     *
     * @param AuthCodeId $authCodeId The authorization code string for which to fetch data.
     *
     * @return null|AuthCode
     *
     * @see     http://tools.ietf.org/html/rfc6749#section-4.1
     */
    public function find(AuthCodeId $authCodeId);

    /**
     * Revoke the auth code.
     *
     * @param AuthCode $code
     */
    public function revoke(AuthCode $code);

    // Auth Code updater
}
