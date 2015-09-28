<?php

namespace OAuth2\Endpoint;

use OAuth2\Behaviour\CanLoadJWT;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasScopeManager;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationFactory
{
    use HasScopeManager;
    use HasClientManagerSupervisor;
    use HasExceptionManager;
    use CanLoadJWT;

    /**
     * {@inheritdoc}
     */
    public function createFromRequest(ServerRequestInterface $request)
    {
        $params = $request->getQueryParams();
        if (isset($params['request'])) {
            return $this->createFromRequestParameter($params);
        } elseif (isset($params['request_uri'])) {
            return $this->createFromRequestUriParameter($params);
        }

        return $this->createFromStandardRequest($params);
    }

    /**
     * @param array $params
     *
     * @return \OAuth2\Endpoint\AuthorizationInterface
     */
    public function createFromRequestParameter(array $params)
    {
    }

    /**
     * @param array $params
     *
     * @return \OAuth2\Endpoint\AuthorizationInterface
     */
    public function createFromRequestUriParameter(array $params)
    {
    }

    /**
     * @param array $params
     *
     * @return \OAuth2\Endpoint\AuthorizationInterface
     */
    public function createFromStandardRequest(array $params)
    {
        $authorization = new Authorization();
        $methods = [
            'setRedirectUri'  => 'redirect_uri',
            'setResponseMode' => 'response_mode',
            'setResponseType' => 'response_type',
            'setScope'        => 'scope',
            'setState'        => 'state',
        ];

        foreach ($methods as $method => $param) {
            $authorization->$method(isset($params['$param']) ? $params['$param'] : null);
        }
        $this->populateClient($authorization);
        /*$authorization->setClient()
        $authorization->setIssueRefreshToken()
        $authorization->setRedirectUri()*/

        return $authorization;
    }

    private function populateClient(Authorization &$authorization)
    {
        if (!isset($params['client_id'])) {
            return;
        }
        $client = $this->getClientManagerSupervisor()->getClient($params['client_id']);
        if (null === $client) {
            return;
        }
        $authorization->setClient($client);
    }
}
