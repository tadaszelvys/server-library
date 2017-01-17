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

namespace OAuth2\Command\Client;

use OAuth2\Model\Client\Client;

final class DeleteClientCommand
{
    /**
     * @var Client
     */
    private $client;

    /**
     * DeleteClientCommand constructor.
     *
     * @param Client $client
     */
    protected function __construct(Client $client)
    {
        $this->client = $client;
    }

    /**
     * @param Client $client
     *
     * @return DeleteClientCommand
     */
    public static function create(Client $client): DeleteClientCommand
    {
        return new self($client);
    }

    /**
     * @return Client
     */
    public function getClient(): Client
    {
        return $this->client;
    }
}
