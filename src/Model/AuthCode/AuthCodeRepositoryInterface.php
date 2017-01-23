<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
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
     * @param AuthCodeId $authCodeId
     *
     * @return bool
     */
    public function has(AuthCodeId $authCodeId): bool;

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
     * @param AuthCodeId $codeId
     */
    public function revoke(AuthCodeId $codeId);

    // Auth Code updater
}
