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
            if (null !== ($client)) {
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
            $client = $manager->findClient($request);
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
        $auth_scheme = $this->getAuthorizationScheme($request);

        if (null === $auth_scheme) {
            return $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_CLIENT, 'Unknown client');
        }

        $schemes = [];
        $all_schemes = [];
        foreach ($this->getClientManagers() as $manager) {
            $manager_schemes = $manager->getSchemesParameters();
            $all_schemes = array_merge($all_schemes, $manager_schemes);
            if (array_key_exists($auth_scheme, $manager_schemes)) {
                $schemes[$auth_scheme] = $manager_schemes[$auth_scheme];
            }
        }
        if (empty($schemes)) {
            $schemes = $all_schemes;
        }

        return $this->getExceptionManager()->getException(ExceptionManagerInterface::AUTHENTICATE, ExceptionManagerInterface::INVALID_CLIENT, 'Client authentication failed.', ['schemes' => $schemes]);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return string|null
     */
    private function getAuthorizationScheme(ServerRequestInterface $request)
    {
        $authHeader = $request->getHeader('Authorization');
        $server_params = $request->getServerParams();
        if (array_key_exists('PHP_AUTH_USER', $server_params)) {
            return 'Basic';
        } elseif (array_key_exists('PHP_AUTH_DIGEST', $server_params)) {
            return 'Digest';
        } elseif (count($authHeader) > 0) {
            if (false !== $pos = strpos($authHeader[0], ' ')) {
                return substr($authHeader[0], 0, $pos);
            } else {
                return $authHeader[0];
            }
        }
    }
}
