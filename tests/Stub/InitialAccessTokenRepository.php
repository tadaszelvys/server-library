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

namespace OAuth2\Test\Stub;

use OAuth2\Event\InitialAccessTokenId\InitialAccessTokenRevokedEvent;
use OAuth2\Model\InitialAccessToken\InitialAccessToken;
use OAuth2\Model\InitialAccessToken\InitialAccessTokenId;
use OAuth2\Model\InitialAccessToken\InitialAccessTokenRepositoryInterface;
use OAuth2\Model\UserAccount\UserAccountId;
use Ramsey\Uuid\Uuid;
use SimpleBus\Message\Recorder\RecordsMessages;

class InitialAccessTokenRepository implements InitialAccessTokenRepositoryInterface
{
    /**
     * @var InitialAccessToken[]
     */
    private $initialAccessTokens = [];

    /**
     * @var RecordsMessages
     */
    private $eventRecorder;

    /**
     * InitialAccessTokenRepository constructor.
     *
     * @param RecordsMessages $eventRecorder
     */
    public function __construct(RecordsMessages $eventRecorder)
    {
        $this->eventRecorder = $eventRecorder;
        $valid_initialAccessToken = InitialAccessToken::create(
            InitialAccessTokenId::create('INITIAL_ACCESS_TOKEN_VALID'),
            UserAccountId::create('user1'),
            new \DateTimeImmutable('now +1 hour')
        );
        $this->save($valid_initialAccessToken);

        $expired_initialAccessToken = InitialAccessToken::create(
            InitialAccessTokenId::create('INITIAL_ACCESS_TOKEN_EXPIRED'),
            UserAccountId::create('user1'),
            new \DateTimeImmutable('now -1 hour')
        );
        $this->save($expired_initialAccessToken);
    }

    /**
     * {@inheritdoc}
     */
    public function create(UserAccountId $userAccountId, \DateTimeImmutable $expiresAt = null)
    {
        $initialAccessTokeId = InitialAccessTokenId::create(Uuid::uuid4()->toString());

        return InitialAccessToken::create($initialAccessTokeId, $userAccountId, $expiresAt);
    }

    /**
     * {@inheritdoc}
     */
    public function save(InitialAccessToken $initialAccessToken)
    {
        $this->initialAccessTokens[(string) $initialAccessToken->getId()] = $initialAccessToken;
        $events = $initialAccessToken->recordedMessages();
        foreach ($events as $event) {
            $this->eventRecorder->record($event);
        }
        $initialAccessToken->eraseMessages();
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(InitialAccessTokenId $initialAccessTokenId)
    {
        if (isset($this->initialAccessTokens[(string) $initialAccessTokenId])) {
            unset($this->initialAccessTokens[(string) $initialAccessTokenId]);
            $event = InitialAccessTokenRevokedEvent::create($initialAccessTokenId);
            $this->eventRecorder->record($event);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function find(InitialAccessTokenId $initialAccessTokenId)
    {
        return array_key_exists((string) $initialAccessTokenId, $this->initialAccessTokens) ? $this->initialAccessTokens[(string) $initialAccessTokenId] : null;
    }
}
