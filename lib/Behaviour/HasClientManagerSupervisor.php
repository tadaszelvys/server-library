<?php

namespace OAuth2\Behaviour;

use OAuth2\Client\ClientManagerSupervisorInterface;

trait HasClientManagerSupervisor
{
    /**
     * @var \OAuth2\Client\ClientManagerSupervisorInterface
     */
    protected $client_manager_supervisor;

    /**
     * @return \OAuth2\Client\ClientManagerSupervisorInterface
     */
    public function getClientManagerSupervisor()
    {
        return $this->client_manager_supervisor;
    }

    /**
     * @param \OAuth2\Client\ClientManagerSupervisorInterface $client_manager_supervisor
     *
     * @return self
     */
    public function setClientManagerSupervisor(ClientManagerSupervisorInterface $client_manager_supervisor)
    {
        $this->client_manager_supervisor = $client_manager_supervisor;

        return $this;
    }
}
