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

namespace OAuth2\Event\Client;

use OAuth2\Model\Client\Client;
use OAuth2\Model\Event\Event;

final class ClientUpdatedEvent extends Event
{
    /**
     * @var Client
     */
    private $client;

    /**
     * ClientCreatedEvent constructor.
     *
     * @param Client $client
     */
    protected function __construct(Client $client)
    {
        parent::__construct();
        $this->client = $client;
    }

    /**
     * @param Client $client
     *
     * @return self
     */
    public static function create(Client $client): self
    {
        return new self($client);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): \JsonSerializable
    {
        return $this->client;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        $json['payload'] = [
            'client_id'  => $this->client->getId(),
            'owner_id'   => $this->client->getResourceOwner(),
            'parameters' => $this->client->all(),
        ];

        return $json;
    }
}
