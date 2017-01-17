<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Token;

use Assert\Assertion;
use OAuth2\Model\Client\Client;
use OAuth2\Model\ResourceOwner\ResourceOwner;

class GrantTypeData
{
    /**
     * @var array
     */
    private $metadata = [];

    /**
     * @var array
     */
    private $parameter = [];

    /**
     * @var ResourceOwner
     */
    private $resourceOwner;

    /**
     * @var Client
     */
    private $client;

    /**
     * @var \string[]
     */
    private $scopes = [];

    /**
     * @var bool
     */
    private $issueRefreshToken = false;

    /**
     * @var \string[]
     */
    private $refreshTokenScopes = [];

    /**
     * @param string $key
     * @param $metadata
     *
     * @return GrantTypeData
     */
    public function withMetadata(string $key, $metadata): self
    {
        $clone = clone $this;
        $clone->metadata[$key] = $metadata;

        return $clone;
    }

    /**
     * @return array
     */
    public function getMetadatas(): array
    {
        return $this->metadata;
    }

    /**
     * @param string $key
     *
     * @return mixed
     */
    public function getMetadata(string $key)
    {
        Assertion::true($this->hasMetadata($key), sprintf('The metadata with key \'%s\' does not exist.', $key));

        return $this->metadata[$key];
    }

    /**
     * @param string $key
     *
     * @return bool
     */
    public function hasMetadata(string $key): bool
    {
        return array_key_exists($key, $this->metadata);
    }

    /**
     * @param string $key
     * @param $parameter
     *
     * @return GrantTypeData
     */
    public function withParameter(string $key, $parameter): self
    {
        $clone = clone $this;
        $clone->parameter[$key] = $parameter;

        return $clone;
    }

    /**
     * @return array
     */
    public function getParameters(): array
    {
        return $this->parameter;
    }

    /**
     * @param string $key
     *
     * @return mixed
     */
    public function getParameter(string $key)
    {
        Assertion::true($this->hasParameter($key), sprintf('The parameter with key \'%s\' does not exist.', $key));

        return $this->parameter[$key];
    }

    /**
     * @param string $key
     *
     * @return bool
     */
    public function hasParameter(string $key): bool
    {
        return array_key_exists($key, $this->parameter);
    }

    /**
     * @param Client $client
     *
     * @return GrantTypeData
     */
    public function withClient(Client $client): self
    {
        $clone = clone $this;
        $clone->client = $client;

        return $clone;
    }

    /**
     * @return Client
     */
    public function getClient(): Client
    {
        return $this->client;
    }

    /**
     * @param ResourceOwner $resourceOwner
     *
     * @return GrantTypeData
     */
    public function withResourceOwner(ResourceOwner $resourceOwner): self
    {
        $clone = clone $this;
        $clone->resourceOwner = $resourceOwner;

        return $clone;
    }

    /**
     * @return ResourceOwner
     */
    public function getResourceOwner(): ResourceOwner
    {
        return $this->resourceOwner;
    }

    /**
     * @param \string[] $scopes
     *
     * @return GrantTypeData
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
     * @return GrantTypeData
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
     * @return GrantTypeData
     */
    public function withoutScope(string $scope): self
    {
        if (!$this->hasScope($scope)) {
            return $this;
        }
        $clone = clone $this;
        $key = array_search($scope, $clone->scopes);
        unset($clone->scopes[$key]);

        return $clone;
    }

    /**
     * @param string $scope
     *
     * @return bool
     */
    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes);
    }

    /**
     * @return \string[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @return bool
     */
    public function hasRefreshToken(): bool
    {
        return $this->issueRefreshToken;
    }

    /**
     * @return GrantTypeData
     */
    public function withRefreshToken(): self
    {
        if (true === $this->issueRefreshToken) {
            return $this;
        }
        $clone = clone $this;
        $clone->issueRefreshToken = true;

        return $clone;
    }

    /**
     * @return GrantTypeData
     */
    public function withoutRefreshToken(): self
    {
        if (false === $this->issueRefreshToken) {
            return $this;
        }
        $clone = clone $this;
        $clone->issueRefreshToken = false;

        return $clone;
    }

    /**
     * @return \string[]
     */
    public function getRefreshTokenScopes(): array
    {
        return $this->refreshTokenScopes;
    }

    /**
     * @param \string[] $scopes
     *
     * @return GrantTypeData
     */
    public function withRefreshTokenScopes(array $scopes): self
    {
        $clone = clone $this;
        $clone->refreshTokenScopes = $scopes;

        return $clone;
    }
}
