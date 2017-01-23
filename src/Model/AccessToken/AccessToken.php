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

namespace OAuth2\Model\AccessToken;

use OAuth2\Event\AccessToken\AccessTokenCreatedEvent;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\RefreshToken\RefreshTokenId;
use OAuth2\Model\ResourceOwner\ResourceOwnerId;
use OAuth2\Model\Token\Token;

final class AccessToken extends Token
{
    /**
     * @var null|RefreshTokenId
     */
    private $refreshTokenId;

    /**
     * AccessToken constructor.
     *
     * @param AccessTokenId       $accessTokenId
     * @param ResourceOwnerId     $resourceOwnerId
     * @param ClientId            $clientId
     * @param array               $parameters
     * @param array               $metadatas
     * @param array               $scopes
     * @param \DateTimeImmutable  $expiresAt
     * @param RefreshTokenId|null $refreshTokenId
     */
    protected function __construct(AccessTokenId $accessTokenId, ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt, RefreshTokenId $refreshTokenId = null)
    {
        parent::__construct($accessTokenId, $resourceOwnerId, $clientId, $expiresAt, $parameters, $metadatas, $scopes);
        $this->refreshTokenId = $refreshTokenId;

        $event = AccessTokenCreatedEvent::create($accessTokenId, $resourceOwnerId, $clientId, $parameters, $metadatas, $scopes, $expiresAt, $refreshTokenId);
        $this->record($event);
    }

    /**
     * @param AccessTokenId       $accessTokenId
     * @param ResourceOwnerId     $resourceOwnerId
     * @param ClientId            $clientId
     * @param array               $parameters
     * @param array               $metadatas
     * @param array               $scopes
     * @param \DateTimeImmutable  $expiresAt
     * @param RefreshTokenId|null $refreshTokenId
     *
     * @return AccessToken
     */
    public static function create(AccessTokenId $accessTokenId, ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt, RefreshTokenId $refreshTokenId = null)
    {
        return new self($accessTokenId, $resourceOwnerId, $clientId, $parameters, $metadatas, $scopes, $expiresAt, $refreshTokenId);
    }

    /**
     * @return null|RefreshTokenId
     */
    public function getRefreshTokenId()
    {
        return $this->refreshTokenId;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        $values = [
            'access_token' => $this->getId(),
            'expires_in'   => $this->getExpiresIn(),
        ];
        if (!empty($this->getScopes())) {
            $values['scope'] = implode(' ', $this->getScopes());
        }
        if (!empty($this->getRefreshTokenId())) {
            $values['refresh_token'] = $this->getRefreshTokenId();
        }

        return $values + $this->getParameters();
    }
}
