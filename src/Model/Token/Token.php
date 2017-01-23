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

namespace OAuth2\Model\Token;

use Assert\Assertion;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\ResourceOwner\ResourceOwnerId;
use SimpleBus\Message\Recorder\ContainsRecordedMessages;
use SimpleBus\Message\Recorder\PrivateMessageRecorderCapabilities;

abstract class Token implements \JsonSerializable, ContainsRecordedMessages
{
    use PrivateMessageRecorderCapabilities;

    /**
     * @var TokenId
     */
    private $tokenId;

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
     * Token constructor.
     *
     * @param TokenId            $tokenId
     * @param ResourceOwnerId    $resourceOwnerId
     * @param ClientId           $clientId
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $metadatas
     * @param string[]           $scopes
     */
    protected function __construct(TokenId $tokenId, ResourceOwnerId $resourceOwnerId, ClientId $clientId, \DateTimeImmutable $expiresAt, array $parameters, array $metadatas, array $scopes)
    {
        $this->tokenId = $tokenId;
        $this->resourceOwnerId = $resourceOwnerId;
        $this->clientId = $clientId;
        $this->expiresAt = $expiresAt;
        $this->parameters = $parameters;
        $this->metadatas = $metadatas;
        $this->scopes = $scopes;
    }

    /**
     * @return TokenId
     */
    public function getId(): TokenId
    {
        return $this->tokenId;
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
     * @return ClientId
     */
    public function getClientId(): ClientId
    {
        return $this->clientId;
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
     * @param string $key
     * @param mixed  $value
     *
     * @return self
     */
    public function withParameter(string $key, $value): self
    {
        $clone = clone $this;
        $clone->parameters[$key] = $value;

        return $clone;
    }

    /**
     * @param string $key
     *
     * @return self
     */
    public function withoutParameter(string $key): self
    {
        if (!$this->hasParameter($key)) {
            return $this;
        }
        $clone = clone $this;
        unset($clone->parameters[$key]);

        return $clone;
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
        Assertion::true($this->hasMetadata($key), sprintf('The metadata \'%s\' does not exist.', $key));

        return $this->metadatas;
    }

    /**
     * @param string $key
     * @param mixed  $value
     *
     * @return self
     */
    public function withMetadata(string $key, $value): self
    {
        $clone = clone $this;
        $clone->metadatas[$key] = $value;

        return $clone;
    }

    /**
     * @param string $key
     *
     * @return self
     */
    public function withoutMetadata(string $key): self
    {
        if (!$this->hasMetadata($key)) {
            return $this;
        }
        $clone = clone $this;
        unset($clone->metadatas[$key]);

        return $clone;
    }
}
