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

namespace OAuth2\Model\IdToken;

use OAuth2\Model\Client\ClientId;
use OAuth2\Model\UserAccount\UserAccountId;

class IdToken implements \JsonSerializable
{
    /**
     * @var IdTokenId
     */
    private $idTokenId;

    /**
     * @var null|string
     */
    private $nonce;

    /**
     * @var null|string
     */
    private $at_hash;

    /**
     * @var null|string
     */
    private $c_hash;

    /**
     * @var ClientId
     */
    private $clientId;

    /**
     * @var UserAccountId
     */
    private $userAccountId;

    /**
     * @var \DateTimeImmutable
     */
    private $expiresAt;

    /**
     * @var array
     */
    private $claims;

    /**
     * IdToken constructor.
     *
     * @param IdTokenId          $idTokenId
     * @param ClientId           $clientId
     * @param UserAccountId      $userAccountId
     * @param \DateTimeImmutable $expiresAt
     * @param array              $claims
     * @param string|null        $nonce
     * @param string|null        $at_hash
     * @param string|null        $c_hash
     */
    private function __construct(IdTokenId $idTokenId, ClientId $clientId, UserAccountId $userAccountId, \DateTimeImmutable $expiresAt, array $claims, string $nonce = null, string $at_hash = null, string $c_hash = null)
    {
        $this->idTokenId = $idTokenId;
        $this->clientId = $clientId;
        $this->userAccountId = $userAccountId;
        $this->expiresAt = $expiresAt;
        $this->claims = $claims;
        $this->nonce = $nonce;
        $this->at_hash = $at_hash;
        $this->c_hash = $c_hash;
    }

    /**
     * @param IdTokenId          $idTokenId
     * @param ClientId           $clientId
     * @param UserAccountId      $userAccountId
     * @param \DateTimeImmutable $expiresAt
     * @param array              $claims
     * @param string|null        $nonce
     * @param string|null        $at_hash
     * @param string|null        $c_hash
     *
     * @return IdToken
     */
    public static function create(IdTokenId $idTokenId, ClientId $clientId, UserAccountId $userAccountId, \DateTimeImmutable $expiresAt, array $claims, string $nonce = null, string $at_hash = null, string $c_hash = null)
    {
        return new self($idTokenId, $clientId, $userAccountId, $expiresAt, $claims, $nonce, $at_hash, $c_hash);
    }

    /**
     * @return IdTokenId
     */
    public function getId(): IdTokenId
    {
        return $this->idTokenId;
    }

    /**
     * @return null|string
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * @param string $nonce
     *
     * @return self
     */
    public function withNonce(string $nonce): self
    {
        $clone = clone $this;
        $clone->nonce = $nonce;

        return $clone;
    }

    /**
     * @return self
     */
    public function withoutNonce(): self
    {
        if (null === $this->nonce) {
            return $this;
        }
        $clone = clone $this;
        $clone->nonce = null;

        return $clone;
    }

    /**
     * @return null|string
     */
    public function getAccessTokenHash()
    {
        return $this->at_hash;
    }

    /**
     * @param string $at_hash
     *
     * @return self
     */
    public function withAccessTokenHash(string $at_hash): self
    {
        $clone = clone $this;
        $clone->at_hash = $at_hash;

        return $clone;
    }

    /**
     * @return self
     */
    public function withoutAccessTokenHash(): self
    {
        if (null === $this->at_hash) {
            return $this;
        }
        $clone = clone $this;
        $clone->at_hash = null;

        return $clone;
    }

    /**
     * @return null|string
     */
    public function getAuthorizationCodeHash()
    {
        return $this->c_hash;
    }

    /**
     * @param string $c_hash
     *
     * @return IdToken
     */
    public function withAuthorizationCodeHash(string $c_hash)
    {
        $clone = clone $this;
        $clone->c_hash = $c_hash;

        return $clone;
    }

    /**
     * @return self
     */
    public function withoutAuthorizationCodeHash(): self
    {
        if (null === $this->c_hash) {
            return $this;
        }
        $clone = clone $this;
        $clone->c_hash = null;

        return $clone;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize()
    {
        return [
            'id_token' => $this->getId()->getValue(),
        ];
    }

    /**
     * @return ClientId
     */
    public function getClientId(): ClientId
    {
        return $this->clientId;
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
     * @return array
     */
    public function getClaims(): array
    {
        return $this->claims;
    }
}
