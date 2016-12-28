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

final class InitialAccessToken
{
    /**
     * @var InitialAccessTokenId
     */
    protected $initialAccessTokenId;

    /**
     * @var \DateTimeImmutable
     */
    protected $expiresAt;

    /**
     * @var UserAccount
     */
    protected $userAccount;

    /**
     * InitialAccessInitialAccessTokenId constructor.
     *
     * @param InitialAccessTokenId    $initialAccessTokenId
     * @param null|\DateTimeImmutable $expiresAt
     * @param UserAccount             $userAccount
     */
    private function __construct(InitialAccessTokenId $initialAccessTokenId, UserAccount $userAccount, \DateTimeImmutable $expiresAt = null)
    {
        $this->initialAccessTokenId = $initialAccessTokenId;
        $this->expiresAt = $expiresAt;
        $this->userAccount = $userAccount;
    }

    /**
     * @param InitialAccessTokenId    $initialAccessTokenId
     * @param UserAccount             $userAccount
     * @param \DateTimeImmutable|null $expiresAt
     *
     * @return InitialAccessToken
     */
    public static function create(InitialAccessTokenId $initialAccessTokenId, UserAccount $userAccount, \DateTimeImmutable $expiresAt = null): self
    {
        return new self($initialAccessTokenId, $userAccount, $expiresAt);
    }

    /**
     * @return InitialAccessTokenId
     */
    public function getId(): InitialAccessTokenId
    {
        return $this->initialAccessTokenId;
    }

    /**
     * @return UserAccount
     */
    public function getUserAccountPublicId(): UserAccount
    {
        return $this->userAccount;
    }

    /**
     * @return \DateTimeImmutable
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    /**
     * @return bool
     */
    public function hasExpired(): bool
    {
        $now = new \DateTimeImmutable();

        return $this->expiresAt->getTimestamp() < $now->getTimestamp();
    }
}
