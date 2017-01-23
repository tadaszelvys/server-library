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

use OAuth2\Event\RefreshToken\RefreshTokenRevokedEvent;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\RefreshToken\RefreshToken;
use OAuth2\Model\RefreshToken\RefreshTokenId;
use OAuth2\Model\RefreshToken\RefreshTokenRepositoryInterface;
use OAuth2\Model\ResourceOwner\ResourceOwnerId;
use OAuth2\Model\UserAccount\UserAccountId;
use SimpleBus\Message\Recorder\RecordsMessages;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    /**
     * @var RefreshToken[]
     */
    private $refreshTokens = [];

    /**
     * @var RecordsMessages
     */
    private $eventRecorder;

    /**
     * RefreshTokenRepository constructor.
     *
     * @param RecordsMessages $eventRecorder
     */
    public function __construct(RecordsMessages $eventRecorder)
    {
        $this->eventRecorder = $eventRecorder;
        $this->refreshTokens['EXPIRED_REFRESH_TOKEN'] = RefreshToken::create(
            RefreshTokenId::create('EXPIRED_REFRESH_TOKEN'),
            UserAccountId::create('User #1'),
            ClientId::create('client1'),
            [],
            new \DateTimeImmutable('now -2 day'),
            [],
            []
        );

        $this->refreshTokens['VALID_REFRESH_TOKEN'] = RefreshToken::create(
            RefreshTokenId::create('VALID_REFRESH_TOKEN'),
            UserAccountId::create('User #1'),
            ClientId::create('client1'),
            [],
            new \DateTimeImmutable('now +2 day'),
            [],
            []
        );
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(RefreshTokenId $refreshTokenId)
    {
        if ($this->has($refreshTokenId)) {
            unset($this->refreshTokens[$refreshTokenId->getValue()]);
            $event = RefreshTokenRevokedEvent::create($refreshTokenId);
            $this->eventRecorder->record($event);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function has(RefreshTokenId $refreshTokenId): bool
    {
        return array_key_exists($refreshTokenId->getValue(), $this->refreshTokens);
    }

    /**
     * {@inheritdoc}
     */
    public function find(RefreshTokenId $tokenId)
    {
        if ($this->has($tokenId)) {
            return $this->refreshTokens[$tokenId->getValue()];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function create(ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $parameters, \DateTimeImmutable $expiresAt, array $scopes, array $metadatas)
    {
        return RefreshToken::create(
            RefreshTokenId::create(base64_encode(random_bytes(50))),
            $resourceOwnerId,
            $clientId,
            $parameters,
            $expiresAt,
            $scopes,
            $metadatas
        );
    }

    /**
     * {@inheritdoc}
     */
    public function save(RefreshToken $token)
    {
        $this->refreshTokens[$token->getId()->getValue()] = $token;
        $events = $token->recordedMessages();
        foreach ($events as $event) {
            $this->eventRecorder->record($event);
        }
        $token->eraseMessages();
    }
}
