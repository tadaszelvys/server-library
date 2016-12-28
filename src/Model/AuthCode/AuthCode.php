<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\AuthCode;

use Assert\Assertion;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\UserAccount\UserAccountId;

final class AuthCode
{
    /**
     * @var bool
     */
    private $issueRefreshToken;

    /**
     * @var array
     */
    private $queryParameters;

    /**
     * @var array
     */
    private $metadatas;

    /**
     * @var string[]
     */
    private $scopes;

    /**
     * @var ClientId
     */
    private $clientId;

    /**
     * @var UserAccountId
     */
    private $userAccountId;

    /**
     * @var array
     */
    private $parameters;

    /**
     * @var AuthCodeId
     */
    private $authCodeId;

    /**
     * @var \DateTimeImmutable
     */
    private $expiresAt;

    /**
     * AuthCode constructor.
     *
     * @param AuthCodeId         $authCodeId
     * @param ClientId           $clientId
     * @param UserAccountId      $userAccountId
     * @param array              $queryParameters
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $scopes
     * @param array              $metadatas
     */
    private function __construct(AuthCodeId $authCodeId, ClientId $clientId, UserAccountId $userAccountId, array $queryParameters, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas)
    {
        $this->authCodeId = $authCodeId;
        $this->clientId = $clientId;
        $this->userAccountId = $userAccountId;
        $this->queryParameters = $queryParameters;
        $this->expiresAt = $expiresAt;
        $this->parameters = $parameters;
        $this->scopes = $scopes;
        $this->metadatas = $metadatas;
    }

    /**
     * @param AuthCodeId         $authCodeId
     * @param ClientId           $clientId
     * @param UserAccountId      $userAccountId
     * @param array              $queryParameters
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $scopes
     * @param array              $metadatas
     *
     * @return AuthCode
     */
    public static function create(AuthCodeId $authCodeId, ClientId $clientId, UserAccountId $userAccountId, array $queryParameters, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas)
    {
        return new self($authCodeId, $clientId, $userAccountId, $queryParameters, $expiresAt, $parameters, $scopes, $metadatas);
    }

    /**
     * @return AuthCodeId
     */
    public function getAuthCodeId(): AuthCodeId
    {
        return $this->authCodeId;
    }

    /**
     * @return UserAccountId
     */
    public function getUserAccountId(): UserAccountId
    {
        return $this->userAccountId;
    }

    /**
     * @return \DateTimeImmutable
     */
    public function getExpiresAt()
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
     * @return array
     */
    public function getParameters(): array
    {
        return $this->parameters;
    }

    /**
     * @param array $parameters
     *
     * @return self
     */
    public function withParameters(array $parameters): self
    {
        $clone = clone $this;
        $clone->parameters = $parameters;

        return $clone;
    }

    /**
     * @param string $key
     * @param mixed  $parameter
     *
     * @return self
     */
    public function withParameter(string $key, $parameter): self
    {
        $clone = clone $this;
        $clone->parameters[$key] = $parameter;

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
     * @param string $key
     *
     * @return mixed
     */
    public function getParameter(string $key)
    {
        Assertion::true($this->hasParameter($key), sprintf('Parameter with key \'%s\' does not exist.', $key));

        return $this->parameters[$key];
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
     * @param string $key
     *
     * @return mixed
     */
    public function getMetadatas(string $key): mixed
    {
        Assertion::true($this->hasMetadata($key), sprintf('Metadata with key \'%s\' does not exist.', $key));

        return $this->metadatas[$key];
    }

    /**
     * @param array $metadatas
     *
     * @return self
     */
    public function withMetadatas(array $metadatas): self
    {
        $clone = clone $this;
        $clone->metadatas = $metadatas;

        return $clone;
    }

    /**
     * @param string $key
     * @param mixed  $metadata
     *
     * @return self
     */
    public function withMetadata(string $key, $metadata): self
    {
        $clone = clone $this;
        $clone->metadatas[$key] = $metadata;

        return $clone;
    }

    /**
     * @param string $key
     *
     * @return self
     */
    public function withoutMetadata(string $key): self
    {
        if (!$this->hasParameter($key)) {
            return $this;
        }

        $clone = clone $this;
        unset($clone->metadatas[$key]);

        return $clone;
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
     * @return bool
     */
    public function isRefreshTokenIssued(): bool
    {
        return $this->issueRefreshToken;
    }

    /**
     * @return self
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
     * @return self
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
     * @return array
     */
    public function getQueryParams(): array
    {
        return $this->queryParameters;
    }

    /**
     * @param string $key
     *
     * @return mixed
     */
    public function getQueryParam(string $key): mixed
    {
        Assertion::true($this->hasQueryParams($key), sprintf('Query parameter with key \'%s\' does not exist.', $key));

        return $this->queryParameters[$key];
    }

    /**
     * @param string $key
     *
     * @return bool
     */
    public function hasQueryParams(string $key): bool
    {
        return array_key_exists($key, $this->getQueryParams());
    }
}
