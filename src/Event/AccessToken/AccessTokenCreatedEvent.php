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

namespace OAuth2\Event\AccessToken;

use OAuth2\Model\AccessToken\AccessTokenId;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Event\Event;
use OAuth2\Model\RefreshToken\RefreshTokenId;
use OAuth2\Model\ResourceOwner\ResourceOwnerId;

final class AccessTokenCreatedEvent extends Event
{
    /**
     * @var AccessTokenId
     */
    private $accessTokenId;

    /**
     * @var null|RefreshTokenId
     */
    private $refreshTokenId;

    /**
     * @var \DateTimeImmutable
     */
    private $expiresAt;

    /**
     * @var ResourceOwnerId
     */
    private $resourceOwnerId;

    /**
     * @var ClientId
     */
    private $clientId;

    /**
     * @var array
     */
    private $parameters;

    /**
     * @var array
     */
    private $metadatas;

    /**
     * @var string[]
     */
    private $scopes;

    /**
     * AccessTokenCreatedEvent constructor.
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
        parent::__construct();

        $this->accessTokenId = $accessTokenId;
        $this->resourceOwnerId = $resourceOwnerId;
        $this->clientId = $clientId;
        $this->parameters = $parameters;
        $this->metadatas = $metadatas;
        $this->scopes = $scopes;
        $this->expiresAt = $expiresAt;
        $this->refreshTokenId = $refreshTokenId;
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
     * @return self
     */
    public static function create(AccessTokenId $accessTokenId, ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt, RefreshTokenId $refreshTokenId = null): self
    {
        return new self($accessTokenId, $resourceOwnerId, $clientId, $parameters, $metadatas, $scopes, $expiresAt, $refreshTokenId);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'access_token_id' => $this->accessTokenId,
            'resource_owner'  => $this->resourceOwnerId,
            'clientId'        => $this->clientId,
            'parameters'      => $this->parameters,
            'metadatas'       => $this->metadatas,
            'scopes'          => $this->scopes,
            'expires_at'      => $this->expiresAt->getTimestamp(),
            'refresh_token'   => $this->refreshTokenId ? $this->refreshTokenId : null,
        ];
    }
}
