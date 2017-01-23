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

use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Event\Event;

final class ClientDeletedEvent extends Event
{
    /**
     * @var ClientId
     */
    private $clientId;

    /**
     * ClientCreatedEvent constructor.
     *
     * @param ClientId $clientId
     */
    protected function __construct(ClientId $clientId)
    {
        parent::__construct();
        $this->clientId = $clientId;
    }

    /**
     * @param ClientId $clientId
     *
     * @return self
     */
    public static function create(ClientId $clientId): self
    {
        return new self($clientId);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'client_id' => $this->clientId,
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        $json = parent::jsonSerialize();
        $json['payload'] = [
            'client_id' => $this->clientId,
        ];

        return $json;
    }
}