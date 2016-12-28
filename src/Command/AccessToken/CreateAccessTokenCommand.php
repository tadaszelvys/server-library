<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\AccessToken;

use Assert\Assertion;
use OAuth2\Model\Client\Client;
use OAuth2\Model\ResourceOwner\ResourceOwner;

final class CreateAccessTokenCommand
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
     * CreateAccessTokenCommand constructor.
     *
     * @param ResourceOwner      $resourceOwner
     * @param Client             $client
     * @param array              $parameters
     * @param array              $metadatas
     * @param string[]           $scopes
     * @param \DateTimeImmutable $expiresAt
     */
    protected function __construct(ResourceOwner $resourceOwner, Client $client, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt)
    {
        $this->resourceOwner = $resourceOwner;
        $this->client = $client;
        $this->expiresAt = $expiresAt;
        $this->parameters = $parameters;
        $this->scopes = $scopes;
        $this->metadatas = $metadatas;
    }

    /**
     * @param ResourceOwner      $resourceOwner
     * @param Client             $client
     * @param array              $parameters
     * @param array              $metadatas
     * @param string[]           $scopes
     * @param \DateTimeImmutable $expiresAt
     *
     * @return CreateAccessTokenCommand
     */
    public static function create(ResourceOwner $resourceOwner, Client $client, array $parameters, array $metadatas, array $scopes, \DateTimeImmutable $expiresAt): CreateAccessTokenCommand
    {
        return new self($resourceOwner, $client, $parameters, $metadatas, $scopes, $expiresAt);
    }

    /**
     * @return \string[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
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
     * @return Client
     */
    public function getClient(): Client
    {
        return $this->client;
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
        Assertion::true($this->hasParameter($key), sprintf('The metadata \'%s\' does not exist.', $key));

        return $this->metadatas;
    }
}
