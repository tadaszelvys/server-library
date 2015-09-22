<?php

namespace OAuth2\Client;

use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Exception\ExceptionManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class ClientManagerSupervisor implements ClientManagerSupervisorInterface
{
    use HasExceptionManager;
    use HasConfiguration;

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
        throw $this->buildAuthenticationException($request);
    }

    /**
     * {@inheritdoc}
     */
    public function buildAuthenticationException(ServerRequestInterface $request)
    {
        $authHeader = $request->getHeader('Authorization');
        $auth_scheme = null;
        $server_params = $request->getServerParams();
        if (array_key_exists('PHP_AUTH_USER', $server_params)) {
            $auth_scheme = 'Basic';
        } elseif (array_key_exists('PHP_AUTH_DIGEST', $server_params)) {
            $auth_scheme = 'Digest';
        } elseif (count($authHeader) > 0 && (0 !== $pos = strpos($authHeader[0], ' '))) {
            $auth_scheme = substr($authHeader[0], 0, $pos);
        }

        if (is_null($auth_scheme)) {
            return $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'Unknown client');
        }
        $params = ['scheme' => $auth_scheme];
        if ('Digest' === $auth_scheme) {
            $qop = $this->getConfiguration()->get('digest_authentication_scheme_quality_of_protection', 'auth,auth-int');
            $params['nonce'] = uniqid();
            $params['opaque'] = hash('md5', $this->getConfiguration()->get('realm', 'Service'));
            $algorithm = $this->configuration->get('digest_authentication_scheme_algorithm', null);

            if (null !== $qop) {
                $params['qop'] = $qop;
            }
            if (null !== $algorithm) {
                $params['algorithm'] = $algorithm;
            }
        }

        return $this->getExceptionManager()->getException(ExceptionManagerInterface::AUTHENTICATE, ExceptionManagerInterface::INVALID_CLIENT, 'Unknown client', $params);
    }
}
