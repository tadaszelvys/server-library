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

namespace OAuth2\Model\AuthCode;

use Assert\Assertion;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Token\Token;
use OAuth2\Model\UserAccount\UserAccount;
use Psr\Http\Message\UriInterface;

final class AuthCode extends Token
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
     * @var AuthCodeId
     */
    private $authCodeId;

    /**
     * @var UriInterface
     */
    private $redirectUri;

    /**
     * AuthCode constructor.
     *
     * @param AuthCodeId         $authCodeId
     * @param Client             $client
     * @param UserAccount        $userAccount
     * @param array              $queryParameters
     * @param UriInterface       $redirectUri
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $scopes
     * @param array              $metadatas
     */
    protected function __construct(AuthCodeId $authCodeId, Client $client, UserAccount $userAccount, array $queryParameters, UriInterface $redirectUri, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas)
    {
        parent::__construct($userAccount, $client, $expiresAt, $parameters, $metadatas, $scopes);
        $this->authCodeId = $authCodeId;
        $this->queryParameters = $queryParameters;
    }

    /**
     * @param AuthCodeId         $authCodeId
     * @param Client             $client
     * @param UserAccount        $userAccount
     * @param array              $queryParameters
     * @param UriInterface       $redirectUri
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $scopes
     * @param array              $metadatas
     *
     * @return AuthCode
     */
    public static function create(AuthCodeId $authCodeId, Client $client, UserAccount $userAccount, array $queryParameters, UriInterface $redirectUri, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas)
    {
        return new self($authCodeId, $client, $userAccount, $queryParameters, $redirectUri, $expiresAt, $parameters, $scopes, $metadatas);
    }

    /**
     * @return AuthCodeId
     */
    public function getId(): AuthCodeId
    {
        return $this->authCodeId;
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

    /**
     * @return UriInterface
     */
    public function getRedirectUri(): UriInterface
    {
        return $this->redirectUri;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return $this->getId()->getValue();
    }
}
