<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\RefreshToken\RefreshToken;
use OAuth2\Model\RefreshToken\RefreshTokenId;
use OAuth2\Model\RefreshToken\RefreshTokenRepositoryInterface;
use OAuth2\Model\ResourceOwner\ResourceOwner;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\Model\UserAccount\UserAccountId;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    /**
     * @var RefreshToken[]
     */
    private $refreshTokens = [];

    public function __construct()
    {
        $this->save(RefreshToken::create(
            RefreshTokenId::create('EXPIRED_REFRESH_TOKEN'),
            UserAccount::create(
                UserAccountId::create('User #1'),
                []
            ),
            Client::create(
                ClientId::create('client1'),
                [],
                UserAccount::create(
                    UserAccountId::create('User #1'),
                    []
                )
            ),
            [],
            new \DateTimeImmutable('now -2 day'),
            [],
            []
        ));

        $this->save(RefreshToken::create(
            RefreshTokenId::create('VALID_REFRESH_TOKEN'),
            UserAccount::create(
                UserAccountId::create('User #1'),
                []
            ),
            Client::create(
                ClientId::create('client1'),
                [],
                UserAccount::create(
                    UserAccountId::create('User #1'),
                    []
                )
            ),
            [],
            new \DateTimeImmutable('now +2 day'),
            [],
            []
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(RefreshToken $refreshToken)
    {
        if ($this->has($refreshToken->getId())) {
            unset($this->refreshTokens[$refreshToken->getId()->getValue()]);
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

    public function create(ResourceOwner $resourceOwner, Client $client, array $parameters, \DateTimeImmutable $expiresAt, array $scopes, array $metadatas)
    {
        return RefreshToken::create(
            RefreshTokenId::create(base64_encode(random_bytes(50))),
            $resourceOwner,
            $client,
            $parameters,
            $expiresAt,
            $scopes,
            $metadatas
        );
    }

    public function save(RefreshToken $token)
    {
        $this->refreshTokens[$token->getId()->getValue()] = $token;
    }
}
