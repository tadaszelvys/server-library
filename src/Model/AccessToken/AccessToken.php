<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\AccessToken;

use Assert\Assertion;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\ResourceOwner\ResourceOwnerId;

final class AccessToken
{
    /**
     * @var AccessTokenId
     */
    private $accessTokenId;

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
     * AccessToken constructor.
     *
     * @param AccessTokenId      $accessTokenId
     * @param ResourceOwnerId    $resourceOwnerId
     * @param ClientId           $clientId
     * @param array              $parameters
     * @param array              $metadatas
     * @param string[]           $scopes
     * @param \DateTimeImmutable $expiresAt
     */
    private function __construct(AccessTokenId $accessTokenId, ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt)
    {
        $this->accessTokenId = $accessTokenId;
        $this->resourceOwnerId = $resourceOwnerId;
        $this->clientId = $clientId;
        $this->expiresAt = $expiresAt;
        $this->parameters = $parameters;
        $this->metadatas = $metadatas;
        $this->scopes = $scopes;
    }

    /**
     * @param AccessTokenId      $accessTokenId
     * @param ResourceOwnerId    $resourceOwnerId
     * @param ClientId           $clientId
     * @param array              $parameters
     * @param array              $metadatas
     * @param string[]           $scopes
     * @param \DateTimeImmutable $expiresAt
     *
     * @return AccessToken
     */
    public static function create(AccessTokenId $accessTokenId, ResourceOwnerId $resourceOwnerId, ClientId $clientId, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt)
    {
        return new self($accessTokenId, $resourceOwnerId, $clientId, $parameters, $metadatas, $scopes, $expiresAt);
    }

    /**
     * @return AccessTokenId
     */
    public function getId(): AccessTokenId
    {
        return $this->accessTokenId;
    }

    /**
     * @return ResourceOwnerId
     */
    public function getResourceOwnerId(): ResourceOwnerId
    {
        return $this->resourceOwnerId;
    }

    /**
     * @return \DateTimeImmutable
     */
    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    /**
     * @return bool
     */
    public function hasExpired(): bool
    {
        return $this->expiresAt->getTimestamp() < time();
    }

    /**
     * {@inheritdoc}
     */
    public function getExpiresIn(): int
    {
        $expiresAt = $this->expiresAt;
        if (null === $expiresAt) {
            return 0;
        }

        return $this->expiresAt->getTimestamp() - time() < 0 ? 0 : $this->expiresAt->getTimestamp() - time();
    }

    /**
     * @param string $scope
     *
     * @return bool
     */
    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->getScopes());
    }

    /**
     * @param string[] $scopes
     *
     * @return self
     */
    public function withScopes(array $scopes): self
    {
        $clone = clone $this;
        $clone->scopes = $scopes;

        return $clone;
    }

    /**
     * @param string $scope
     *
     * @return self
     */
    public function withScope(string $scope): self
    {
        if ($this->hasScope($scope)) {
            return $this;
        }
        $clone = clone $this;
        $clone->scopes[] = $scope;

        return $clone;
    }

    /**
     * @param string $scope
     *
     * @return self
     */
    public function withoutScope(string $scope): self
    {
        if (!$this->hasScope($scope)) {
            return $this;
        }

        $clone = clone $this;
        unset($clone->scopes[$scope]);

        return $clone;
    }

    /**
     * @return string[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
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
    public function getParameter(string $key): mixed
    {
        Assertion::true($this->hasParameter($key), sprintf('The parameter \'%s\' does not exist.', $key));

        return $this->parameters;
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
    public function getMetadata(string $key): mixed
    {
        Assertion::true($this->hasMetadata($key), sprintf('The metadata \'%s\' does not exist.', $key));

        return $this->metadatas;
    }
}
