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

final class ClientParametersUpdatedEvent extends Event
{
    /**
     * @var ClientId
     */
    private $clientId;

    /**
     * @var array
     */
    private $parameters;

    /**
     * ClientCreatedEvent constructor.
     *
     * @param ClientId $clientId
     * @param array $parameters
     */
    protected function __construct(ClientId $clientId, array $parameters)
    {
        parent::__construct();
        $this->clientId = $clientId;
        $this->parameters = $parameters;
    }

    /**
     * @param ClientId $clientId
     * @param array $parameters
     *
     * @return ClientParametersUpdatedEvent
     */
    public static function create(ClientId $clientId, array $parameters): self
    {
        return new self($clientId, $parameters);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'client_id' => $this->clientId,
            'parameters' => $this->parameters,
        ];
    }
}
