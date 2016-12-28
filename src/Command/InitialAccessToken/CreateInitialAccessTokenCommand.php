<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\InitialAccessToken;

use OAuth2\Model\UserAccount\UserAccount;

final class CreateInitialAccessTokenCommand
{
    /**
     * @var UserAccount
     */
    private $userAccount;

    /**
     * @var \DateTimeImmutable|null
     */
    private $expiresAt;

    /**
     * CreateInitialAccessTokenCommand constructor.
     *
     * @param UserAccount             $userAccount
     * @param \DateTimeImmutable|null $expiresAt
     */
    protected function __construct(UserAccount $userAccount, \DateTimeImmutable $expiresAt = null)
    {
        $this->userAccount = $userAccount;
        $this->expiresAt = $expiresAt;
    }

    /**
     * @param UserAccount             $userAccount
     * @param \DateTimeImmutable|null $expiresAt
     *
     * @return CreateInitialAccessTokenCommand
     */
    public static function create(UserAccount $userAccount, \DateTimeImmutable $expiresAt = null): self
    {
        return new self($userAccount, $expiresAt);
    }

    /**
     * @return UserAccount
     */
    public function getUserAccount(): UserAccount
    {
        return $this->userAccount;
    }

    /**
     * @return null|\DateTimeImmutable
     */
    public function getExpiresAt()
    {
        return $this->expiresAt;
    }
}
