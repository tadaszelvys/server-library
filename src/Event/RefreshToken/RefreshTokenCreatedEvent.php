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

namespace OAuth2\Event\RefreshToken;

use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Event\Event;
use OAuth2\Model\RefreshToken\RefreshTokenId;
use OAuth2\Model\ResourceOwner\ResourceOwnerId;

final class RefreshTokenCreatedEvent extends Event
{
    /**
     * @var RefreshTokenId
     */
    private $refreshTokenId;

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
     * @var \DateTimeImmutable
     */
    private $expiresAt;

    /**
     * @var array
     */
    private $scopes;

    /**
     * @var array
     */
    private $metadatas;

    /**
     * RefreshTokenCreatedEvent constructor.
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
        parent::__construct();
        $this->refreshTokenId = $refreshTokenId;
        $this->resourceOwnerId = $resourceOwnerId;
        $this->clientId = $clientId;
        $this->parameters = $parameters;
        $this->expiresAt = $expiresAt;
        $this->scopes = $scopes;
        $this->metadatas = $metadatas;
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
     * @return self
     */
    public static function create(RefreshTokenId $refreshTokenId, ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $parameters, \DateTimeImmutable $expiresAt, array $scopes, array $metadatas): self
    {
        return new self($refreshTokenId, $resourceOwnerId, $clientId, $parameters, $expiresAt, $scopes, $metadatas);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'refresh_token_id' => $this->refreshTokenId,
            'resource_owner_id' => $this->resourceOwnerId,
            'client_id' => $this->clientId,
            'parameters' => $this->parameters,
            'expires_at' => $this->expiresAt->getTimestamp(),
            'scopes' => $this->scopes,
            'metadatas' => $this->metadatas,
        ];
    }
}
