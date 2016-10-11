<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

use Assert\Assertion;
use OAuth2\Client\ClientManagerInterface;

trait HasClientManager
{
    /**
     * @var \OAuth2\Client\ClientManagerInterface|null
     */
    private $client_manager = null;

    /**
     * @return bool
     */
    protected function hasClientManager()
    {
        return null !== $this->client_manager;
    }

    /**
     * @return \OAuth2\Client\ClientManagerInterface
     */
    protected function getClientManager()
    {
        Assertion::true($this->hasClientManager(), 'The client manager is not available.');

        return $this->client_manager;
    }

    /**
     * @param \OAuth2\Client\ClientManagerInterface $client_manager
     */
    protected function setClientManager(ClientManagerInterface $client_manager)
    {
        $this->client_manager = $client_manager;
    }
}
