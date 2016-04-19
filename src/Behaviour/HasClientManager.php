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

use OAuth2\Client\ClientManagerInterface;

trait HasClientManager
{
    /**
     * @var \OAuth2\Client\ClientManagerInterface
     */
    private $client_manager;

    /**
     * @return \OAuth2\Client\ClientManagerInterface
     */
    protected function getClientManager()
    {
        return $this->client_manager;
    }

    /**
     * @param \OAuth2\Client\ClientManagerInterface $client_manager
     */
    private function setClientManager(ClientManagerInterface $client_manager)
    {
        $this->client_manager = $client_manager;
    }
}
