<?php

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
    protected $client_managers = [];

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
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request, &$client_public_id_found = null)
    {
        foreach ($this->getClientManagers() as $manager) {
            $client = $manager->findClient($request, $client_public_id_found);
            if ($client instanceof ClientInterface) {
                return $client;
            }
        }
        throw $this->buildException($request);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return \OAuth2\Exception\BaseExceptionInterface
     */
    private function buildException(ServerRequestInterface $request)
    {
        $authHeader = $request->getHeader('Authorization');
        $auth_scheme = null;
        if (!is_null($request->getAttribute('PHP_AUTH_USER'))) {
            $auth_scheme = 'Basic';
        } elseif (count($authHeader) > 0 && (0 !== $pos = strpos($authHeader[0], ' '))) {
            $auth_scheme = substr($authHeader[0], 0, $pos);
        }

        if (is_null($auth_scheme)) {
            return $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'Unknown client');
        }

        return $this->getExceptionManager()->getException(ExceptionManagerInterface::AUTHENTICATE, ExceptionManagerInterface::INVALID_CLIENT, 'Unknown client', ['scheme' => $auth_scheme]);
    }
}
