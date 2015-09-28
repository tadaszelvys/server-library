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
     * @return \OAuth2\Endpoint\Authorization
     */
    public function createFromRequestParameter(array $params)
    {
    }

    /**
     * @param array $params
     *
     * @return \OAuth2\Endpoint\Authorization
     */
    public function createFromRequestUriParameter(array $params)
    {
    }

    /**
     * @param array $params
     *
     * @return \OAuth2\Endpoint\Authorization
     */
    public function createFromStandardRequest(array $params)
    {
        $authorization = new Authorization();

        $authorization->setQueryParams($params);

        $methods = [
            'setRedirectUri'  => 'redirect_uri',
            'setResponseMode' => 'response_mode',
            'setResponseType' => 'response_type',
            'setClientId'     => 'client_id',
            'setState'        => 'state',
            'setNonce'        => 'nonce',
            'setClaims'       => 'claims',
            'setMaxAge'       => 'max_age',
            'setDisplay'      => 'display',
            'setPrompt'       => 'prompt',
            'setUiLocales'    => 'ui_locales',
            'setIdTokenHint'  => 'id_token_hint',
            'setLoginHint'    => 'login_hint',
            'setAcrValues'    => 'acr_values',
        ];

        foreach ($methods as $method => $param) {
            $authorization->$method(isset($params['$param']) ? $params['$param'] : null);
        }
        $this->populateClient($params, $authorization);
        $this->populateScope($params, $authorization);
        $this->checkDisplay($authorization);
        $this->checkPrompt($authorization);

        return $authorization;
    }

    private function checkDisplay(Authorization $authorization)
    {
        if (!in_array($authorization->getDisplay(), $authorization->getAllowedDisplayValues())) {
            throw new \InvalidArgumentException('Invalid "display" parameter. Allowed values are '.json_encode($authorization->getAllowedDisplayValues()));
        }
    }

    private function checkPrompt(Authorization $authorization)
    {
        if (!in_array($authorization->getPrompt(), $authorization->getAllowedPromptValues())) {
            throw new \InvalidArgumentException('Invalid "prompt" parameter. Allowed values are '.json_encode($authorization->getAllowedPromptValues()));
        }
    }

    private function populateClient(array $params, Authorization &$authorization)
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

    private function populateScope(array $params, Authorization &$authorization)
    {
        if (!isset($params['scope'])) {
            return;
        }
        $scope = $this->getScopeManager()->convertToScope($params['scope']);

        $authorization->setScope($scope);
    }
}
