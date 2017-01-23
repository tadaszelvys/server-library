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

namespace OAuth2\Model\AuthCode;

use Assert\Assertion;
use OAuth2\Event\AuthCode\AuthCodeCreatedEvent;
use OAuth2\Event\AuthCodeId\AuthCodeWithoutRefreshTokenEvent;
use OAuth2\Event\AuthCodeId\AuthCodeWithRefreshTokenEvent;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Token\Token;
use OAuth2\Model\UserAccount\UserAccountId;
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
     * @var UriInterface
     */
    private $redirectUri;

    /**
     * AuthCode constructor.
     *
     * @param AuthCodeId         $authCodeId
     * @param ClientId           $clientId
     * @param UserAccountId      $userAccountId
     * @param array              $queryParameters
     * @param UriInterface       $redirectUri
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $scopes
     * @param array              $metadatas
     */
    protected function __construct(AuthCodeId $authCodeId, ClientId $clientId, UserAccountId $userAccountId, array $queryParameters, UriInterface $redirectUri, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas)
    {
        parent::__construct($authCodeId, $userAccountId, $clientId, $expiresAt, $parameters, $metadatas, $scopes);
        $this->redirectUri = $redirectUri;
        $this->queryParameters = $queryParameters;

        $event = AuthCodeCreatedEvent::create($authCodeId, $clientId, $userAccountId, $queryParameters, $redirectUri, $expiresAt, $parameters, $scopes, $metadatas);
        $this->record($event);
    }

    /**
     * @param AuthCodeId         $authCodeId
     * @param ClientId           $clientId
     * @param UserAccountId      $userAccountId
     * @param array              $queryParameters
     * @param UriInterface       $redirectUri
     * @param \DateTimeImmutable $expiresAt
     * @param array              $parameters
     * @param array              $scopes
     * @param array              $metadatas
     *
     * @return AuthCode
     */
    public static function create(AuthCodeId $authCodeId, ClientId $clientId, UserAccountId $userAccountId, array $queryParameters, UriInterface $redirectUri, \DateTimeImmutable $expiresAt, array $parameters, array $scopes, array $metadatas)
    {
        return new self($authCodeId, $clientId, $userAccountId, $queryParameters, $redirectUri, $expiresAt, $parameters, $scopes, $metadatas);
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
        $event = AuthCodeWithRefreshTokenEvent::create($clone->getId());
        $this->record($event);

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
        $event = AuthCodeWithoutRefreshTokenEvent::create($clone->getId());
        $this->record($event);

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
        return $this->getId();
    }
}
