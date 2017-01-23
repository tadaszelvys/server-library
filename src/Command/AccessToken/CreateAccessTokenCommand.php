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

namespace OAuth2\Command\AccessToken;

use Assert\Assertion;
use OAuth2\Command\CommandWithDataTransporter;
use OAuth2\DataTransporter;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\ResourceOwner\ResourceOwnerId;

final class CreateAccessTokenCommand extends CommandWithDataTransporter
{
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
     * @var \string[]
     */
    private $scopes;

    /**
     * @var \DateTimeImmutable
     */
    private $expiresAt;

    /**
     * CreateAccessTokenCommand constructor.
     *
     * @param ResourceOwnerId    $resourceOwnerId
     * @param ClientId           $clientId
     * @param array              $parameters
     * @param array              $metadatas
     * @param array              $scopes
     * @param \DateTimeImmutable $expiresAt
     * @param DataTransporter    $dataTransporter
     */
    protected function __construct(ClientId $clientId, ResourceOwnerId $resourceOwnerId, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt, DataTransporter $dataTransporter = null)
    {
        $this->resourceOwnerId = $resourceOwnerId;
        $this->clientId = $clientId;
        $this->parameters = $parameters;
        $this->metadatas = $metadatas;
        $this->scopes = $scopes;
        $this->expiresAt = $expiresAt;
        parent::__construct($dataTransporter);
    }

    /**
     * @param ResourceOwnerId    $resourceOwnerId
     * @param ClientId             $clientId
     * @param array              $parameters
     * @param array              $metadatas
     * @param array              $scopes
     * @param \DateTimeImmutable $expiresAt
     * @param DataTransporter    $dataTransporter
     *
     * @return CreateAccessTokenCommand
     */
    public static function create(ClientId $clientId, ResourceOwnerId $resourceOwnerId, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt, DataTransporter $dataTransporter = null): CreateAccessTokenCommand
    {
        return new self($clientId, $resourceOwnerId, $parameters, $metadatas, $scopes, $expiresAt, $dataTransporter);
    }

    /**
     * @return ResourceOwnerId
     */
    public function getResourceOwnerId(): ResourceOwnerId
    {
        return $this->resourceOwnerId;
    }

    /**
     * @return ClientId
     */
    public function getClientId(): ClientId
    {
        return $this->clientId;
    }

    /**
     * @return array
     */
    public function getParameters(): array
    {
        return $this->parameters;
    }

    /**
     * @param string $key
     *
     * @return bool
     */
    public function hasParameter(string $key): bool
    {
        return array_key_exists($key, $this->parameters);
    }

    /**
     * @param string $key
     *
     * @throws \InvalidArgumentException
     *
     * @return mixed
     */
    public function getParameter(string $key)
    {
        Assertion::true($this->hasParameter($key), sprintf('The parameter \'%s\' does not exist.', $key));

        return $this->parameters[$key];
    }

    /**
     * @return array
     */
    public function getMetadatas(): array
    {
        return $this->metadatas;
    }

    /**
     * @param string $key
     *
     * @return bool
     */
    public function hasMetadata(string $key): bool
    {
        return array_key_exists($key, $this->metadatas);
    }

    /**
     * @param string $key
     *
     * @throws \InvalidArgumentException
     *
     * @return mixed
     */
    public function getMetadata(string $key)
    {
        Assertion::true($this->hasParameter($key), sprintf('The metadata \'%s\' does not exist.', $key));

        return $this->metadatas;
    }

    /**
     * @return \string[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @return \DateTimeImmutable
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }
}
