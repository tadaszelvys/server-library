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

namespace OAuth2\Model\InitialAccessToken;

use OAuth2\Event\InitialAccessToken\InitialAccessTokenCreatedEvent;
use OAuth2\Model\UserAccount\UserAccountId;
use SimpleBus\Message\Recorder\ContainsRecordedMessages;
use SimpleBus\Message\Recorder\PrivateMessageRecorderCapabilities;

final class InitialAccessToken implements ContainsRecordedMessages
{
    use PrivateMessageRecorderCapabilities;

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
     * InitialAccessInitialAccessTokenId constructor.
     *
     * @param InitialAccessTokenId    $initialAccessTokenId
     * @param null|\DateTimeImmutable $expiresAt
     * @param UserAccountId           $userAccountId
     */
    private function __construct(InitialAccessTokenId $initialAccessTokenId, UserAccountId $userAccountId, \DateTimeImmutable $expiresAt = null)
    {
        $this->initialAccessTokenId = $initialAccessTokenId;
        $this->expiresAt = $expiresAt;
        $this->userAccountId = $userAccountId;

        $event = InitialAccessTokenCreatedEvent::create($initialAccessTokenId, $userAccountId, $expiresAt);
        $this->record($event);
    }

    /**
     * @param InitialAccessTokenId    $initialAccessTokenId
     * @param UserAccountId           $userAccountId
     * @param \DateTimeImmutable|null $expiresAt
     *
     * @return InitialAccessToken
     */
    public static function create(InitialAccessTokenId $initialAccessTokenId, UserAccountId $userAccountId, \DateTimeImmutable $expiresAt = null): self
    {
        return new self($initialAccessTokenId, $userAccountId, $expiresAt);
    }

    /**
     * @return InitialAccessTokenId
     */
    public function getId(): InitialAccessTokenId
    {
        return $this->initialAccessTokenId;
    }

    /**
     * @return UserAccountId
     */
    public function getUserAccountId(): UserAccountId
    {
        return $this->userAccountId;
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
