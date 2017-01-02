<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\RefreshToken;

use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\Client\Client;
use OAuth2\Model\ResourceOwner\ResourceOwner;
use OAuth2\Model\Token\Token;

class RefreshToken extends Token
{
    /**
     * @var RefreshTokenId
     */
    private $refreshTokenId;

    /**
     * @var AccessToken[]
     */
    private $accessTokens;

    /**
     * @var array
     */
    private $parameters;

    /**
     * @var string[]
     */
    private $scopes;

    /**
     * RefreshToken constructor.
     * @param RefreshTokenId $refreshTokenId
     * @param ResourceOwner $resourceOwner
     * @param Client $client
     * @param array $parameters
     * @param \DateTimeImmutable $expiresAt
     * @param array $scopes
     */
    protected function __construct(RefreshTokenId $refreshTokenId, ResourceOwner $resourceOwner, Client $client, array $parameters, \DateTimeImmutable $expiresAt, array $scopes)
    {
        parent::__construct($resourceOwner, $client, $expiresAt);
        $this->refreshTokenId = $refreshTokenId;
        $this->parameters = $parameters;
        $this->scopes = $scopes;
    }

    /**
     * @param RefreshTokenId $refreshTokenId
     * @param ResourceOwner $resourceOwner
     * @param Client $client
     * @param array $parameters
     * @param \DateTimeImmutable $expiresAt
     * @param string[] $scopes
     * @return RefreshToken
     */
    public static function create(RefreshTokenId $refreshTokenId, ResourceOwner $resourceOwner, Client $client, array $parameters, \DateTimeImmutable $expiresAt, array $scopes)
    {
        return new self($refreshTokenId, $resourceOwner, $client, $parameters, $expiresAt, $scopes);
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

        return $clone;
    }

    /**
     * @return RefreshTokenId
     */
    public function getId(): RefreshTokenId
    {
        return $this->refreshTokenId;
    }

    /**
     * @return AccessToken[]
     */
    public function getAccessTokens(): array
    {
        return $this->accessTokens;
    }

    /**
     * @return array
     */
    public function getParameters(): array
    {
        return $this->parameters;
    }

    /**
     * @return \string[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return $this->getId()->getValue();
    }
}
