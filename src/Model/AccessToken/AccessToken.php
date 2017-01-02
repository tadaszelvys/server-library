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
        parent::__construct($resourceOwner, $client, $expiresAt);
        $this->accessTokenId = $accessTokenId;
        $this->parameters = $parameters;
        $this->metadatas = $metadatas;
        $this->scopes = $scopes;
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
