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

namespace OAuth2\Command\AccessToken;

use Assert\Assertion;
use OAuth2\Command\CommandWithDataTransporter;
use OAuth2\DataTransporter;
use OAuth2\Model\Client\Client;
use OAuth2\Model\ResourceOwner\ResourceOwner;

final class CreateAccessTokenCommand extends CommandWithDataTransporter
{
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
     * @var \string[]
     */
    private $scopes;

    /**
     * CreateAccessTokenCommand constructor.
     *
     * @param ResourceOwner   $resourceOwner
     * @param Client          $client
     * @param array           $parameters
     * @param array           $metadatas
     * @param array           $scopes
     * @param DataTransporter $dataTransporter
     */
    protected function __construct(Client $client, ResourceOwner $resourceOwner, array $parameters, array $metadatas, array $scopes, DataTransporter $dataTransporter = null)
    {
        $this->resourceOwner = $resourceOwner;
        $this->client = $client;
        $this->parameters = $parameters;
        $this->metadatas = $metadatas;
        $this->scopes = $scopes;
        parent::__construct($dataTransporter);
    }

    /**
     * @param ResourceOwner   $resourceOwner
     * @param Client          $client
     * @param array           $parameters
     * @param array           $metadatas
     * @param array           $scopes
     * @param DataTransporter $dataTransporter
     *
     * @return CreateAccessTokenCommand
     */
    public static function create(Client $client, ResourceOwner $resourceOwner, array $parameters, array $metadatas, array $scopes, DataTransporter $dataTransporter = null): CreateAccessTokenCommand
    {
        return new self($client, $resourceOwner, $parameters, $metadatas, $scopes, $dataTransporter);
    }

    /**
     * @return ResourceOwner
     */
    public function getResourceOwner(): ResourceOwner
    {
        return $this->resourceOwner;
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

    /**
     * @return \string[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }
}
