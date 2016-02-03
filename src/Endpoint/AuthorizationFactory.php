<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint;

use Assert\Assertion;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerSupervisorInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\Util\JWTLoader;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationFactory
{
    use HasJWTLoader;
    use HasScopeManager;
    use HasClientManagerSupervisor;
    use HasExceptionManager;

    /**
     * @var bool
     */
    private $request_parameter_supported = false;

    /**
     * @var bool
     */
    private $request_uri_parameter_supported = false;

    /**
     * AuthorizationFactory constructor.
     *
     * @param \OAuth2\Scope\ScopeManagerInterface             $scope_manager
     * @param \OAuth2\Client\ClientManagerSupervisorInterface $client_manager_supervisor
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     * @param \OAuth2\Util\JWTLoader                          $jwt_loader
     */
    public function __construct(
        ScopeManagerInterface $scope_manager,
        ClientManagerSupervisorInterface $client_manager_supervisor,
        ExceptionManagerInterface $exception_manager,
        JWTLoader $jwt_loader
    ) {
        $this->setJWTLoader($jwt_loader);
        $this->setScopeManager($scope_manager);
        $this->setClientManagerSupervisor($client_manager_supervisor);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * @return bool
     */
    public function isRequestParameterSupported()
    {
        return $this->request_parameter_supported;
    }

    /**
     * @param bool $request_parameter_supported
     */
    public function setRequestParameterSupported($request_parameter_supported)
    {
        Assertion::boolean($request_parameter_supported);
        $this->request_parameter_supported = $request_parameter_supported;
    }

    /**
     * @return bool
     */
    public function isRequestUriParameterSupported()
    {
        return $this->request_uri_parameter_supported;
    }

    /**
     * @param bool $request_uri_parameter_supported
     */
    public function setRequestUriParameterSupported($request_uri_parameter_supported)
    {
        Assertion::boolean($request_uri_parameter_supported);
        $this->request_uri_parameter_supported = $request_uri_parameter_supported;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\EndUser\EndUserInterface         $end_user
     * @param bool                                     $is_authorized
     *
     * @return \OAuth2\Endpoint\Authorization
     */
    public function createFromRequest(ServerRequestInterface $request, EndUserInterface $end_user, $is_authorized)
    {
        $params = $request->getQueryParams();
        if (array_key_exists('request', $params)) {
            $this->createFromRequestParameter();
        } elseif (array_key_exists('request_uri', $params)) {
            $this->createFromRequestUriParameter();
        }

        return $this->createFromStandardRequest($params, $end_user, $is_authorized);
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function createFromRequestParameter()
    {
        if (false === $this->isRequestParameterSupported()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "request" is not supported');
        }
        throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Not supported');
    }

    /**
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function createFromRequestUriParameter()
    {
        if (false === $this->isRequestUriParameterSupported()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "request_uri" is not supported');
        }
        throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Not supported');
    }

    /**
     * @param array                            $params
     * @param \OAuth2\EndUser\EndUserInterface $end_user
     * @param bool                             $is_authorized
     *
     * @return \OAuth2\Endpoint\Authorization
     */
    private function createFromStandardRequest(array $params, EndUserInterface $end_user, $is_authorized)
    {
        $client = $this->getClient($params);
        $scopes = $this->getScope($params);
        $authorization = new Authorization($params, $end_user, $is_authorized, $client, $scopes);

        return $authorization;
    }

    /**
     * @param array $params
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Client\ClientInterface
     */
    private function getClient(array $params)
    {
        $client = array_key_exists('client_id', $params) ? $this->getClientManagerSupervisor()->getClient($params['client_id']) : null;
        if (!$client instanceof ClientInterface) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Parameter "client_id" missing or invalid.');
        }

        return $client;
    }

    /**
     * @param array $params
     *
     * @return \string[]
     */
    private function getScope(array $params)
    {
        if (array_key_exists('scope', $params)) {
            return $this->getScopeManager()->convertToArray($params['scope']);
        }

        return [];
    }
}
