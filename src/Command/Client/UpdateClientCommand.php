<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\Client;

use OAuth2\Command\CommandWithDataTransporter;
use OAuth2\DataTransporter;
use OAuth2\Model\Client\Client;

final class UpdateClientCommand extends CommandWithDataTransporter
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
     * UpdateClientCommand constructor.
     *
     * @param Client          $client
     * @param array           $parameters
     * @param DataTransporter $dataTransporter
     */
    protected function __construct(Client $client, array $parameters, DataTransporter $dataTransporter)
    {
        $this->client = $client;
        $this->parameters = $parameters;
        parent::__construct($dataTransporter);
    }

    /**
     * @param Client          $client
     * @param array           $parameters
     * @param DataTransporter $dataTransporter
     *
     * @return UpdateClientCommand
     */
    public static function create(Client $client, array $parameters, DataTransporter $dataTransporter): self
    {
        return new self($client, $parameters, $dataTransporter);
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
}
