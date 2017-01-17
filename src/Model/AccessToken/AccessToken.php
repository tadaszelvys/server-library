<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\AccessToken;

use OAuth2\Model\Client\Client;
use OAuth2\Model\RefreshToken\RefreshToken;
use OAuth2\Model\ResourceOwner\ResourceOwner;
use OAuth2\Model\Token\Token;

final class AccessToken extends Token
{
    /**
     * @var AccessTokenId
     */
    private $accessTokenId;

    /**
     * @var null|RefreshToken
     */
    private $refreshToken;

    /**
     * AccessToken constructor.
     * @param AccessTokenId $accessTokenId
     * @param ResourceOwner $resourceOwner
     * @param Client $client
     * @param array $parameters
     * @param array $metadatas
     * @param array $scopes
     * @param \DateTimeImmutable $expiresAt
     * @param RefreshToken|null $refreshToken
     */
    protected function __construct(AccessTokenId $accessTokenId, ResourceOwner $resourceOwner, Client $client, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt, RefreshToken $refreshToken = null)
    {
        parent::__construct($resourceOwner, $client, $expiresAt, $parameters, $metadatas, $scopes);
        $this->accessTokenId = $accessTokenId;
        $this->refreshToken = $refreshToken;
    }

    /**
     * @param AccessTokenId $accessTokenId
     * @param ResourceOwner $resourceOwner
     * @param Client $client
     * @param array $parameters
     * @param array $metadatas
     * @param array $scopes
     * @param \DateTimeImmutable $expiresAt
     * @param RefreshToken|null $refreshToken
     * @return AccessToken
     */
    public static function create(AccessTokenId $accessTokenId, ResourceOwner $resourceOwner, Client $client, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt, RefreshToken $refreshToken = null)
    {
        return new self($accessTokenId, $resourceOwner, $client, $parameters, $metadatas, $scopes, $expiresAt, $refreshToken);
    }

    /**
     * @return AccessTokenId
     */
    public function getId(): AccessTokenId
    {
        return $this->accessTokenId;
    }

    /**
     * @return null|RefreshToken
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        $values = [
            'access_token' => $this->getId()->getValue(),
            'expires_in' => $this->getExpiresIn(),
        ];
        if (!empty($this->getScopes())) {
            $values['scope'] = implode(' ', $this->getScopes());
        }
        if (!empty($this->getRefreshToken())) {
            $values['refresh_token'] = $this->getRefreshToken()->getId()->getValue();
        }
        return $values + $this->getParameters();
    }
}
