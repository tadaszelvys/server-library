<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Event\Client;

use OAuth2\Model\Client\Client;
use OAuth2\Model\Event\Event;

final class ClientDeletedEvent extends Event
{
    /**
     * @param array $json
     * @return \JsonSerializable
     */
    protected static function createPayloadFromJson(array $json): \JsonSerializable
    {
        return Client::createFromJson($json['client_id']);
    }

    /**
     * @param Client $client
     * @return self
     */
    public static function create(Client $client): self
    {
        $event = new self($client);

        return $event;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        return [
            'id' => $this->getEventId()->getValue(),
            'type' => self::class,
            'recorded_on' => (float) $this->getRecordedOn()->format('U.u'),
            'payload' => [
                'client_id' => $this->getPayload()->getValue(),
            ],
        ];
    }
}
