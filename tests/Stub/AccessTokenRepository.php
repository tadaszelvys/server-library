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

/*use Jose\JWTCreatorInterface;
use Jose\JWTLoaderInterface;
use Jose\Object\JWKSetInterface;*/
use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\AccessToken\AccessTokenId;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\RefreshToken\RefreshToken;
use OAuth2\Model\RefreshToken\RefreshTokenId;
use OAuth2\Model\ResourceOwner\ResourceOwner;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\Model\UserAccount\UserAccountId;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    /**
     * @var AccessToken[]
     */
    private $accessTokens = [];

    public function __construct()
    {
        $this->save(AccessToken::create(
            AccessTokenId::create('ACCESS_TOKEN_#1'),
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
            [
                'token_type' => 'Bearer',
            ],
            [],
            [],
            new \DateTimeImmutable('now +3600 seconds'),
            RefreshToken::create(
                RefreshTokenId::create('REFRESH_TOKEN_#1'),
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
                new \DateTimeImmutable('now +2 days'),
                [],
                []
            )
        ));

        $this->save(AccessToken::create(
            AccessTokenId::create('ACCESS_TOKEN_#2'),
            UserAccount::create(
                UserAccountId::create('User #1'),
                []
            ),
            Client::create(
                ClientId::create('client2'),
                [],
                UserAccount::create(
                    UserAccountId::create('User #1'),
                    []
                )
            ),
            [],
            [],
            [],
            new \DateTimeImmutable('now +3600 seconds'),
            RefreshToken::create(
                RefreshTokenId::create('REFRESH_TOKEN_#1'),
                UserAccount::create(
                    UserAccountId::create('User #1'),
                    []
                ),
                Client::create(
                    ClientId::create('client2'),
                    [],
                    UserAccount::create(
                        UserAccountId::create('User #1'),
                        []
                    )
                ),
                [],
                new \DateTimeImmutable('now +2 days'),
                [],
                []
            )
        ));
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(AccessToken $accessToken)
    {
        if ($this->has($accessToken->getId())) {
            unset($this->accessTokens[$accessToken->getId()->getValue()]);
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
        return array_key_exists($tokenId->getValue(), $this->accessTokens) ? $this->accessTokens[$tokenId->getValue()] : $this->loadAccessToken($tokenId);
    }

    public function create(ResourceOwner $resourceOwner, Client $client, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt, RefreshToken $refreshToken = null)
    {
        return AccessToken::create(
            AccessTokenId::create(bin2hex(random_bytes(50))),
            $resourceOwner,
            $client,
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
    }

    /**
     * @param AccessTokenId $tokenId
     *
     * @return null|AccessToken
     */
    private function loadAccessToken(AccessTokenId $tokenId)
    {
    }
}
