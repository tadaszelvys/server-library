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

use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\AuthCode\AuthCodeId;
use OAuth2\Model\AuthCode\AuthCodeRepositoryInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\Model\UserAccount\UserAccountId;
use Zend\Diactoros\Uri;

class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    /**
     * @var AuthCode[]
     */
    private $authCodes = [];

    /**
     * AuthCodeRepository constructor.
     */
    public function __construct()
    {
        $this->save(AuthCode::create(
            AuthCodeId::create('VALID_AUTH_CODE'),
            ClientId::create('client1'),
            UserAccountId::create('john.doe.1'),
            [],
            new Uri(),
            new \DateTimeImmutable('now +1 day'),
            [],
            [],
            []
        ));
    }

    /**
     * @param AuthCode $authCode
     */
    public function save(AuthCode $authCode)
    {
        $this->authCodes[$authCode->getId()->getValue()] = $authCode;
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(AuthCode $code)
    {
        if (array_key_exists($code->getId()->getValue(), $this->authCodes)) {
            unset($this->authCodes[$code->getId()->getValue()]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function create(Client $client, UserAccount $userAccount, array $queryParameters, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas)
    {
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
