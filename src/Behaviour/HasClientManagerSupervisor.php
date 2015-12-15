<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

use OAuth2\Client\ClientManagerSupervisorInterface;

trait HasClientManagerSupervisor
{
    /**
     * @var \OAuth2\Client\ClientManagerSupervisorInterface
     */
    private $client_manager_supervisor;

    /**
     * @return \OAuth2\Client\ClientManagerSupervisorInterface
     */
    protected function getClientManagerSupervisor()
    {
        return $this->client_manager_supervisor;
    }

    /**
     * @param \OAuth2\Client\ClientManagerSupervisorInterface $client_manager_supervisor
     */
    private function setClientManagerSupervisor(ClientManagerSupervisorInterface $client_manager_supervisor)
    {
        $this->client_manager_supervisor = $client_manager_supervisor;
    }
}
