<?php

namespace OAuth2\Client;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Symfony\Component\HttpFoundation\Request;

class ClientManagerSupervisor implements ClientManagerSupervisorInterface
{
    use HasExceptionManager;

    /**
     * @var \OAuth2\Client\ClientManagerInterface[]
     */
    private $client_managers = [];

    /**
     * {@inheritdoc}
     */
    protected function getClientManagers()
    {
        return $this->client_managers;
    }

    /**
     * @param \OAuth2\Client\ClientManagerInterface $client_manager
     *
     * @return self
     */
    public function addClientManager(ClientManagerInterface $client_manager)
    {
        $this->client_managers[] = $client_manager;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        foreach ($this->getClientManagers() as $manager) {
            $client = $manager->getClient($client_id);
            if (!is_null($client)) {
                return $client;
            }
        }

        return;
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(Request $request, $throw_exception_if_not_found = true)
    {
        foreach ($this->getClientManagers() as $manager) {
            $client = $manager->findClient($request);
            if ($client instanceof ClientInterface) {
                return $client;
            } elseif (is_string($client)) {
                throw $this->buildException($request);
            }
        }
        if (true === $throw_exception_if_not_found) {
            throw $this->buildException($request);
        }

        return;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \OAuth2\Exception\BaseExceptionInterface
     */
    private function buildException(Request $request)
    {
        $auth_scheme = null;
        if (!is_null($request->server->get('PHP_AUTH_USER'))) {
            $auth_scheme = 'Basic';
        } elseif (!is_null($authHeader = $request->headers->get('Authorization')) && (0 !== $pos = strpos($authHeader, ' '))) {
            $auth_scheme = substr($authHeader, 0, $pos);
        }

        if (is_null($auth_scheme)) {
            return $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'Unknown client');
        }

        return $this->getExceptionManager()->getException(ExceptionManagerInterface::AUTHENTICATE, ExceptionManagerInterface::INVALID_CLIENT, 'Unknown client', ['scheme' => $auth_scheme]);
    }
}
