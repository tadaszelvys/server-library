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

final class ClientParameterRemovedEvent extends Event
{
    /**
     * @var ClientId
     */
    private $clientId;

    /**
     * @var string
     */
    private $key;

    /**
     * ClientParameterUpdatedEvent constructor.
     *
     * @param ClientId $clientId
     * @param string   $key
     */
    protected function __construct(ClientId $clientId, string $key)
    {
        parent::__construct();
        $this->clientId = $clientId;
        $this->key = $key;
    }

    /**
     * @param ClientId $clientId
     * @param string   $key
     *
     * @return ClientParameterRemovedEvent
     */
    public static function create(ClientId $clientId, string $key): self
    {
        return new self($clientId, $key);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'client_id' => $this->clientId,
            'key' => $this->key,
        ];
    }
}
