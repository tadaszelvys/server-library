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

use OAuth2\Event\AccessToken\AccessTokenRevokedEvent;
use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\AccessToken\AccessTokenId;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\RefreshToken\RefreshToken;
use OAuth2\Model\RefreshToken\RefreshTokenId;
use OAuth2\Model\ResourceOwner\ResourceOwnerId;
use OAuth2\Model\UserAccount\UserAccountId;
use SimpleBus\Message\Recorder\RecordsMessages;
use Zend\Diactoros\Uri;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    /**
     * @var AccessToken[]
     */
    private $accessTokens = [];

    /**
     * @var RecordsMessages
     */
    private $eventRecorder;

    /**
     * AccessTokenRepository constructor.
     *
     * @param RecordsMessages $eventRecorder
     */
    public function __construct(RecordsMessages $eventRecorder)
    {
        $this->eventRecorder = $eventRecorder;
        $this->accessTokens['ACCESS_TOKEN_#1'] = AccessToken::create(
            AccessTokenId::create('ACCESS_TOKEN_#1'),
            UserAccountId::create('User #1'),
            ClientId::create('client1'),
            [
                'token_type' => 'Bearer',
            ],
            [],
            [],
            new \DateTimeImmutable('now +3600 seconds'),
            RefreshTokenId::create('REFRESH_TOKEN_#1')
        );

        $this->accessTokens['ACCESS_TOKEN_#2'] = AccessToken::create(
            AccessTokenId::create('ACCESS_TOKEN_#2'),
            UserAccountId::create('User #1'),
            ClientId::create('client2'),
            [],
            [],
            [],
            new \DateTimeImmutable('now +3600 seconds'),
            RefreshTokenId::create('REFRESH_TOKEN_#1')
        );

        $this->accessTokens['VALID_ACCESS_TOKEN_FOR_USERINFO'] = AccessToken::create(
            AccessTokenId::create('VALID_ACCESS_TOKEN_FOR_USERINFO'),
            UserAccountId::create('john.1'),
            ClientId::create('client2'),
            [
                'token_type' => 'Bearer',
            ],
            [
                'redirect_uri' => new Uri('http://127.0.0.1:8080'),
            ],
            ['openid', 'profile', 'email', 'phone', 'address'],
            new \DateTimeImmutable('now +3600 seconds'),
            null
        );

        $this->accessTokens['INVALID_ACCESS_TOKEN_FOR_USERINFO'] = AccessToken::create(
            AccessTokenId::create('INVALID_ACCESS_TOKEN_FOR_USERINFO'),
            UserAccountId::create('john.1'),
            ClientId::create('client2'),
            [
                'token_type' => 'Bearer',
            ],
            [
                'redirect_uri' => new Uri('http://127.0.0.1:8080'),
            ],
            [],
            new \DateTimeImmutable('now +3600 seconds'),
            null
        );

        $this->accessTokens['ACCESS_TOKEN_ISSUED_THROUGH_TOKEN_ENDPOINT'] = AccessToken::create(
            AccessTokenId::create('ACCESS_TOKEN_ISSUED_THROUGH_TOKEN_ENDPOINT'),
            UserAccountId::create('john.1'),
            ClientId::create('client2'),
            [
                'token_type' => 'Bearer',
            ],
            [],
            ['openid', 'profile', 'email', 'phone', 'address'],
            new \DateTimeImmutable('now +3600 seconds'),
            null
        );
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(AccessTokenId $accessTokenId)
    {
        if ($this->has($accessTokenId)) {
            unset($this->accessTokens[$accessTokenId->getValue()]);
            $event = AccessTokenRevokedEvent::create($accessTokenId);
            $this->eventRecorder->record($event);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function has(AccessTokenId $accessTokenId): bool
    {
        return array_key_exists($accessTokenId->getValue(), $this->accessTokens);
    }

    /**
     * {@inheritdoc}
     */
    public function find(AccessTokenId $tokenId)
    {
        return array_key_exists($tokenId->getValue(), $this->accessTokens) ? $this->accessTokens[$tokenId->getValue()] : null;
    }

    public function create(ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt, RefreshToken $refreshToken = null)
    {
        return AccessToken::create(
            AccessTokenId::create(bin2hex(random_bytes(50))),
            $resourceOwnerId,
            $clientId,
            $parameters,
            $metadatas,
            $scopes,
            $expiresAt,
            $refreshToken
        );
    }

    public function save(AccessToken $token)
    {
        $this->accessTokens[$token->getId()->getValue()] = $token;
        $events = $token->recordedMessages();
        foreach ($events as $event) {
            $this->eventRecorder->record($event);
        }
        $token->eraseMessages();
    }
}
