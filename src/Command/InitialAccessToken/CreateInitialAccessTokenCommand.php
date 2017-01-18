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

namespace OAuth2\Command\InitialAccessToken;

use OAuth2\Command\CommandWithDataTransporter;
use OAuth2\DataTransporter;
use OAuth2\Model\UserAccount\UserAccount;

final class CreateInitialAccessTokenCommand extends CommandWithDataTransporter
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
     * @param DataTransporter|null    $dataTransporter
     */
    protected function __construct(UserAccount $userAccount, \DateTimeImmutable $expiresAt = null, DataTransporter $dataTransporter = null)
    {
        $this->userAccount = $userAccount;
        $this->expiresAt = $expiresAt;
        parent::__construct($dataTransporter);
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
