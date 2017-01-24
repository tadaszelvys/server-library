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

use OAuth2\Event\AuthCode\AuthCodeRevokedEvent;
use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\AuthCode\AuthCodeId;
use OAuth2\Model\AuthCode\AuthCodeRepositoryInterface;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\UserAccount\UserAccountId;
use Psr\Http\Message\UriInterface;
use SimpleBus\Message\Recorder\RecordsMessages;
use Zend\Diactoros\Uri;

class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    /**
     * @var AuthCode[]
     */
    private $authCodes = [];

    /**
     * @var RecordsMessages
     */
    private $eventRecorder;

    /**
     * AuthCodeRepository constructor.
     *
     * @param RecordsMessages $eventRecorder
     */
    public function __construct(RecordsMessages $eventRecorder)
    {
        $this->eventRecorder = $eventRecorder;
        $this->authCodes['VALID_AUTH_CODE'] = AuthCode::create(
            AuthCodeId::create('VALID_AUTH_CODE'),
            ClientId::create('client1'),
            UserAccountId::create('john.doe.1'),
            [],
            new Uri('https://www.example.com/callback'),
            new \DateTimeImmutable('now +1 day'),
            [],
            ['openid', 'email', 'phone', 'address'],
            []
        );

        $this->authCodes['EXPIRED_AUTH_CODE'] = AuthCode::create(
            AuthCodeId::create('EXPIRED_AUTH_CODE'),
            ClientId::create('client1'),
            UserAccountId::create('john.doe.1'),
            [],
            new Uri('https://www.example.com/callback'),
            new \DateTimeImmutable('now -1 day'),
            [],
            ['openid', 'email', 'phone', 'address'],
            []
        );
    }

    /**
     * @param AuthCode $authCode
     */
    public function save(AuthCode $authCode)
    {
        $this->authCodes[$authCode->getId()->getValue()] = $authCode;
        $events = $authCode->recordedMessages();
        foreach ($events as $event) {
            $this->eventRecorder->record($event);
        }
        $authCode->eraseMessages();
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(AuthCodeId $codeId)
    {
        if ($this->has($codeId)) {
            unset($this->authCodes[$codeId->getValue()]);
            $event = AuthCodeRevokedEvent::create($codeId);
            $this->eventRecorder->record($event);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function create(ClientId $clientId, UserAccountId $userAccountId, array $queryParameters, UriInterface $redirectUri, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas)
    {
        return AuthCode::create(
            AuthCodeId::create(bin2hex(random_bytes(50))),
            $clientId,
            $userAccountId,
            $queryParameters,
            $redirectUri,
            $expiresAt,
            $parameters,
            $scopes,
            $metadatas
        );
    }

    /**
     * {@inheritdoc}
     */
    public function has(AuthCodeId $authCodeId): bool
    {
        return array_key_exists($authCodeId->getValue(), $this->authCodes);
    }

    /**
     * {@inheritdoc}
     */
    public function find(AuthCodeId $authCodeId)
    {
        return $this->has($authCodeId) ? $this->authCodes[$authCodeId->getValue()] : null;
    }
}
