<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\Client;

use OAuth2\DataTransporter;
use OAuth2\Model\Client\Client;

final class UpdateClientCommand
{
    /**
     * @var Client
     */
    private $client;

    /**
     * @var array
     */
    private $parameters;

    /**
     * @var DataTransporter
     */
    private $callback;

    /**
     * UpdateClientCommand constructor.
     *
     * @param Client          $client
     * @param array           $parameters
     * @param DataTransporter $callback
     */
    protected function __construct(Client $client, array $parameters, DataTransporter $callback)
    {
        $this->client = $client;
        $this->parameters = $parameters;
        $this->callback = $callback;
    }

    /**
     * @param Client          $client
     * @param array           $parameters
     * @param DataTransporter $callback
     *
     * @return UpdateClientCommand
     */
    public static function create(Client $client, array $parameters, DataTransporter $callback): self
    {
        return new self($client, $parameters, $callback);
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
     * @return DataTransporter
     */
    public function getCallback(): DataTransporter
    {
        return $this->callback;
    }
}
