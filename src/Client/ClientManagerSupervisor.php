<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class ClientManagerSupervisor implements ClientManagerSupervisorInterface
{
    use HasExceptionManager;

    /**
     * @var \OAuth2\Client\ClientManagerInterface[]
     */
    private $client_managers = [];

    /**
     * ClientManagerSupervisor constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @return \OAuth2\Client\ClientManagerInterface[]
     */
    private function getClientManagers()
    {
        return $this->client_managers;
    }

    /**
     * @param \OAuth2\Client\ClientManagerInterface $client_manager
     */
    public function addClientManager(ClientManagerInterface $client_manager)
    {
        $this->client_managers[] = $client_manager;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        foreach ($this->getClientManagers() as $manager) {
            $client = $manager->getClient($client_id);
            if (null !== $client) {
                return $client;
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request)
    {
        foreach ($this->getClientManagers() as $manager) {
            $client = $manager->findClient($request, $client_credentials);
            if ($client instanceof ClientInterface && true === $manager->isClientSupported($client)) {
                $is_authenticated = $manager->isClientAuthenticated($client, $client_credentials, $request, $reason);

                if (true === $is_authenticated) {
                    return $client;
                } else {
                    throw $this->buildAuthenticationException($request, $reason);
                }
            }
        }
        throw $this->buildAuthenticationException($request);
    }

    /**
     * {@inheritdoc}
     */
    public function buildAuthenticationException(ServerRequestInterface $request, $reason = null)
    {
        $schemes = [];
        $message = 'Client authentication failed.';
        if (is_string($reason)) {
            $message .= sprintf(' %s', $reason);
        }
        foreach ($this->getClientManagers() as $manager) {
            $manager_schemes = $manager->getSchemesParameters();
            $schemes = array_merge($schemes, $manager_schemes);
        }

        return $this->getExceptionManager()->getAuthenticateException(
            ExceptionManagerInterface::INVALID_CLIENT,
            $message,
            ['schemes' => $schemes]
        );
    }
    
    /**
     * {@inheritdoc}
     */
    public function getSupportedAuthenticationMethods()
    {
        $methods = [];
        foreach ($this->getClientManagers() as $manager) {
            $methods = array_merge(
                $manager->getSupportedAuthenticationMethods(),
                $methods
            );
        }
        
        return array_unique($methods);
    }
}
