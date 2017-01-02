<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\Token;

use OAuth2\Model\Client\Client;
use OAuth2\Model\ResourceOwner\ResourceOwner;

abstract class Token implements \JsonSerializable
{
    /**
     * @var \DateTimeImmutable
     */
    private $expiresAt;

    /**
     * @var ResourceOwner
     */
    private $resourceOwner;

    /**
     * @var Client
     */
    private $client;

    /**
     * AccessToken constructor.
     * @param ResourceOwner $resourceOwner
     * @param Client $client
     * @param \DateTimeImmutable $expiresAt
     */
    protected function __construct(ResourceOwner $resourceOwner, Client $client, \DateTimeImmutable $expiresAt)
    {
        $this->resourceOwner = $resourceOwner;
        $this->client = $client;
        $this->expiresAt = $expiresAt;
    }

    /**
     * @return ResourceOwner
     */
    public function getResourceOwner(): ResourceOwner
    {
        return $this->resourceOwner;
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
     * @return Client
     */
    public function getClient(): Client
    {
        return $this->client;
    }
}
