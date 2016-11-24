<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\RefreshToken;

use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;

class RefreshToken
{
    /**
     * @var RefreshTokenId
     */
    private $refreshTokenId;

    /**
     * @var AccessToken[]
     */
    private $accessTokens;

    /**
     * @var \DateTimeImmutable
     */
    private $expiresAt;

    /**
     * @var UserAccount
     */
    private $userAccount;

    /**
     * @var Client
     */
    private $client;

    /**
     * @var array
     */
    private $parameters;

    /**
     * RefreshToken constructor.
     * @param RefreshTokenId $refreshTokenId
     * @param UserAccount $userAccount
     * @param Client $client
     * @param array $parameters
     * @param \DateTimeImmutable $expiresAt
     */
    private function __construct(RefreshTokenId $refreshTokenId, UserAccount $userAccount, Client $client, array $parameters, \DateTimeImmutable $expiresAt)
    {
        $this->refreshTokenId = $refreshTokenId;
        $this->userAccount = $userAccount;
        $this->client = $client;
        $this->expiresAt = $expiresAt;
        $this->parameters = $parameters;
    }

    /**
     * @param RefreshTokenId $refreshTokenId
     * @param UserAccount $userAccount
     * @param Client $client
     * @param array $parameters
     * @param \DateTimeImmutable $expiresAt
     * @return RefreshToken
     */
    public static function create(RefreshTokenId $refreshTokenId, UserAccount $userAccount, Client $client, array $parameters, \DateTimeImmutable $expiresAt)
    {
        return new self($refreshTokenId, $userAccount, $client, $parameters, $expiresAt);
    }

    /**
     * @param AccessToken $accessToken
     * @return RefreshToken
     */
    public function withAccessToken(AccessToken $accessToken): RefreshToken
    {
        $id = $accessToken->getId()->getValue();
        if (array_key_exists($id, $this->accessTokens)) {
            return $this;
        }

        $clone = clone $this;
        $clone->accessTokens[$id] = $accessToken;

        return $clone;
    }

    /**
     * @return RefreshTokenId
     */
    public function getRefreshTokenId(): RefreshTokenId
    {
        return $this->refreshTokenId;
    }

    /**
     * @return AccessToken[]
     */
    public function getAccessTokens(): array
    {
        return $this->accessTokens;
    }

    /**
     * @return \DateTimeImmutable
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    /**
     * @return UserAccount
     */
    public function getUserAccount(): UserAccount
    {
        return $this->userAccount;
    }

    /**
     * @return Client
     */
    public function getClient(): Client
    {
        return $this->client;
    }

    /**
     * @return array
     */
    public function getParameters(): array
    {
        return $this->parameters;
    }
}
