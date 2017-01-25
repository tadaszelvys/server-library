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

final class ClientParameterUpdatedEvent extends Event
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
     * @var mixed|null
     */
    private $value;

    /**
     * ClientParameterUpdatedEvent constructor.
     *
     * @param ClientId   $clientId
     * @param string     $key
     * @param mixed|null $value
     */
    protected function __construct(ClientId $clientId, string $key, $value)
    {
        parent::__construct();
        $this->clientId = $clientId;
        $this->key = $key;
        $this->value = $value;
    }

    /**
     * @param ClientId   $clientId
     * @param string     $key
     * @param mixed|null $value
     *
     * @return ClientParameterUpdatedEvent
     */
    public static function create(ClientId $clientId, string $key, $value): self
    {
        return new self($clientId, $key, $value);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'client_id' => $this->clientId,
            'key'       => $this->key,
            'value'     => $this->value,
        ];
    }
}
