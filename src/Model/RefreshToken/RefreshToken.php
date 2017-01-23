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

namespace OAuth2\Model\RefreshToken;

use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\ResourceOwner\ResourceOwnerId;
use OAuth2\Model\Token\Token;

class RefreshToken extends Token
{
    /**
     * @var AccessToken[]
     */
    private $accessTokens;

    /**
     * RefreshToken constructor.
     *
     * @param RefreshTokenId     $refreshTokenId
     * @param ResourceOwnerId    $resourceOwnerId
     * @param ClientId           $clientId
     * @param array              $parameters
     * @param \DateTimeImmutable $expiresAt
     * @param array              $scopes
     * @param array              $metadatas
     */
    protected function __construct(RefreshTokenId $refreshTokenId, ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $parameters, \DateTimeImmutable $expiresAt, array $scopes, array $metadatas)
    {
        parent::__construct($refreshTokenId, $resourceOwnerId, $clientId, $expiresAt, $parameters, $metadatas, $scopes);
    }

    /**
     * @param RefreshTokenId     $refreshTokenId
     * @param ResourceOwnerId    $resourceOwnerId
     * @param ClientId           $clientId
     * @param array              $parameters
     * @param \DateTimeImmutable $expiresAt
     * @param array              $scopes
     * @param array              $metadatas
     *
     * @return RefreshToken
     */
    public static function create(RefreshTokenId $refreshTokenId, ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $parameters, \DateTimeImmutable $expiresAt, array $scopes, array $metadatas)
    {
        return new self($refreshTokenId, $resourceOwnerId, $clientId, $parameters, $expiresAt, $scopes, $metadatas);
    }

    /**
     * @param AccessToken $accessToken
     *
     * @return RefreshToken
     */
    public function withAccessToken(AccessToken $accessToken): RefreshToken
    {
        $id = $accessToken->getId()->getValue();
        if (array_key_exists($id, $this->accessTokens)) {
            return $this;
        }

        $clone = clone $this;
        $clone->accessTokens[$id] = $accessToken;
        //$event = AccessTokenAddedToRefreshTokenEvent::create($accessToken->getId());
        //$this->record($event);

        return $clone;
    }

    /**
     * @return AccessToken[]
     */
    public function getAccessTokens(): array
    {
        return $this->accessTokens;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return $this->getId();
    }
}
