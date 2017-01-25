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

namespace OAuth2\Event\InitialAccessToken;

use OAuth2\Model\Event\Event;
use OAuth2\Model\InitialAccessToken\InitialAccessTokenId;
use OAuth2\Model\UserAccount\UserAccountId;

final class InitialAccessTokenCreatedEvent extends Event
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
     * @var UserAccountId
     */
    protected $userAccountId;

    /**
     * InitialAccessTokenCreatedEvent constructor.
     *
     * @param InitialAccessTokenId    $initialAccessTokenId
     * @param null|\DateTimeImmutable $expiresAt
     * @param UserAccountId           $userAccountId
     */
    protected function __construct(InitialAccessTokenId $initialAccessTokenId, UserAccountId $userAccountId, \DateTimeImmutable $expiresAt = null)
    {
        parent::__construct();
        $this->initialAccessTokenId = $initialAccessTokenId;
        $this->expiresAt = $expiresAt;
        $this->userAccountId = $userAccountId;
    }

    /**
     * @param InitialAccessTokenId    $initialAccessTokenId
     * @param null|\DateTimeImmutable $expiresAt
     * @param UserAccountId           $userAccountId
     *
     * @return self
     */
    public static function create(InitialAccessTokenId $initialAccessTokenId, UserAccountId $userAccountId, \DateTimeImmutable $expiresAt = null): self
    {
        return new self($initialAccessTokenId, $userAccountId, $expiresAt);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'initial_access_token_id' => $this->initialAccessTokenId,
            'user_account_id'         => $this->userAccountId,
            'expires_at'              => $this->expiresAt ? $this->expiresAt->getTimestamp() : null,
        ];
    }
}
