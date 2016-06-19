<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use Assert\Assertion;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Client\ClientInterface;
use OAuth2\Endpoint\Authorization\ParameterChecker\DisplayParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\NonceParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerInterface;
use OAuth2\Endpoint\Authorization\ParameterChecker\PromptParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\RedirectUriParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\ResponseModeParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\ResponseTypeParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\ScopeParameterChecker;
use OAuth2\Endpoint\Authorization\ParameterChecker\StateParameterChecker;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\ResponseTypeInterface;
use OAuth2\ResponseMode\ResponseModeInterface;
use OAuth2\Scope\ScopeManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationFactory implements AuthorizationFactoryInterface
{
    use HasJWTLoader;
    use HasExceptionManager;

    /**
     * @var \OAuth2\ResponseMode\ResponseModeInterface[]
     */
    private $response_modes = [];

    /**
     * @var \OAuth2\Grant\ResponseTypeInterface[]
     */
    private $response_types = [];

    /**
     * @var \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerInterface[]
     */
    private $parameter_checkers = [];

    /**
     * @var \OAuth2\Endpoint\Authorization\AuthorizationRequestLoaderInterface
     */
    private $authorization_request_loader;

    /**
     * @var bool
     */
    private $response_mode_parameter_in_authorization_request_enabled = true;

    /**
     * AuthorizationFactory constructor.
     *
     * @param \OAuth2\Endpoint\Authorization\AuthorizationRequestLoaderInterface $authorization_request_loader
     * @param \OAuth2\Scope\ScopeManagerInterface                                $scope_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                        $exception_manager
     * @param bool                                                               $state_parameter_enforced
     * @param bool                                                               $secured_redirect_uri_enforced
     * @param bool                                                               $redirect_uri_storage_enforced
     * @param bool                                                               $response_mode_parameter_in_authorization_request_allowed
     */
    public function __construct(
        AuthorizationRequestLoaderInterface $authorization_request_loader,
        ScopeManagerInterface $scope_manager,
        ExceptionManagerInterface $exception_manager,
        $state_parameter_enforced = true,
        $secured_redirect_uri_enforced = true,
        $redirect_uri_storage_enforced = true,
        $response_mode_parameter_in_authorization_request_allowed = false
    ) {
        Assertion::boolean($response_mode_parameter_in_authorization_request_allowed);
        $this->authorization_request_loader = $authorization_request_loader;
        $this->setExceptionManager($exception_manager);

        $this->addParameterChecker(new DisplayParameterChecker());
        $this->addParameterChecker(new PromptParameterChecker());
        $this->addParameterChecker(new ResponseTypeParameterChecker());
        $this->addParameterChecker(new StateParameterChecker($state_parameter_enforced));
        $this->addParameterChecker(new ScopeParameterChecker($scope_manager));
        $this->addParameterChecker(new RedirectUriParameterChecker($secured_redirect_uri_enforced, $redirect_uri_storage_enforced));
        $this->addParameterChecker(new ResponseModeParameterChecker($response_mode_parameter_in_authorization_request_allowed));
        $this->addParameterChecker(new NonceParameterChecker());
    }

    /**
     * {@inheritdoc}
     */
    public function addParameterChecker(ParameterCheckerInterface $parameter_checker)
    {
        $this->parameter_checkers[] = $parameter_checker;
    }

    /**
     * {@inheritdoc}
     */
    public function isResponseModeParameterSupported()
    {
        return $this->response_mode_parameter_in_authorization_request_enabled;
    }

    /**
     * {@inheritdoc}
     */
    public function enableResponseModeParameterSupport()
    {
        $this->response_mode_parameter_in_authorization_request_enabled = true;
    }

    /**
     * {@inheritdoc}
     */
    public function disableResponseModeParameterSupport()
    {
        $this->response_mode_parameter_in_authorization_request_enabled = false;
    }

    /**
     * {@inheritdoc}
     */
    public function addResponseType(ResponseTypeInterface $response_type)
    {
        $type = $response_type->getResponseType();
        if (!array_key_exists($type, $this->response_types)) {
            $this->response_types[$type] = $response_type;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseTypesSupported()
    {
        $types = array_keys($this->response_types);
        if (in_array('id_token', $types)) {
            if (in_array('code', $types)) {
                $types[] = 'code id_token';
            }
            if (in_array('token', $types)) {
                $types[] = 'id_token token';
            }
            if (in_array('code', $types) && in_array('token', $types)) {
                $types[] = 'code id_token token';
            }
        }
        if (in_array('code', $types) && in_array('token', $types)) {
            $types[] = 'code token';
        }

        return $types;
    }

    /**
     * {@inheritdoc}
     */
    public function addResponseMode(ResponseModeInterface $response_mode)
    {
        $name = $response_mode->getName();
        if (!array_key_exists($name, $this->response_modes)) {
            $this->response_modes[$name] = $response_mode;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseModesSupported()
    {
        return array_keys($this->response_modes);
    }

    /**
     * {@inheritdoc}
     */
    public function createAuthorizationFromRequest(ServerRequestInterface $request)
    {
        $parameters = $this->authorization_request_loader->loadParametersFromRequest($request);
        $client = $parameters['client'];

        $this->checkParameters($client, $parameters);

        $types = $this->getResponseTypes($client, $parameters);
        $response_mode = $this->getResponseMode($parameters, $types);

        $redirect_uri = $parameters['redirect_uri'];
        $scope = array_key_exists('scope', $parameters) ? $parameters['scope'] : [];

        return new Authorization($parameters, $client, $types, $response_mode, $redirect_uri, $scope);
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $parameters
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     */
    private function checkParameters(ClientInterface $client, array &$parameters)
    {
        foreach ($this->parameter_checkers as $parameter_checker) {
            try {
                $parameter_checker->checkerParameter($client, $parameters);
            } catch (\InvalidArgumentException $e) {
                throw $this->getExceptionManager()->getBadRequestException($parameter_checker->getError(), $e->getMessage());
            }
        }
    }

    /**
     * @param array                                        $params
     * @param \OAuth2\Grant\ResponseTypeInterface[] $types
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\ResponseMode\ResponseModeInterface
     */
    private function getResponseMode(array $params, array $types)
    {
        if (array_key_exists('response_mode', $params) && true === $this->isResponseModeParameterSupported()) {
            return $this->getResponseModeService($params['response_mode']);
        }

        if (1 === count($types)) {
            // There is only one type (OAuth2 request)
            $mode = $types[0]->getResponseMode();
        } else {
            //There are multiple response types
            $mode = $this->getResponseModeIfMultipleResponseTypes($params['response_type']);
        }
        
        return $this->getResponseModeService($mode);
    }

    /**
     * @param string $response_type
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return string
     */
    private function getResponseModeIfMultipleResponseTypes($response_type)
    {
        switch ($response_type) {
            case 'code token':
            case 'code id_token':
            case 'id_token token':
            case 'code id_token token':
                return 'fragment';
            default:
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, sprintf('Unsupported response type combination "%s".', $response_type));
        }
    }

    /**
     * @param string $mode
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\ResponseMode\ResponseModeInterface
     */
    private function getResponseModeService($mode)
    {
        if (!array_key_exists($mode, $this->response_modes)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, sprintf('Unsupported response mode "%s".', $mode));
        }

        return $this->response_modes[$mode];
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $params
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Grant\ResponseTypeInterface[]
     */
    private function getResponseTypes(ClientInterface $client, array $params)
    {
        if (!in_array($params['response_type'], $this->getResponseTypesSupported())) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, sprintf('Response type "%s" is not supported by this server', $params['response_type']));
        }
        if (!$client->isResponseTypeAllowed($params['response_type'])) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::UNAUTHORIZED_CLIENT, 'The response type "'.$params['response_type'].'" is unauthorized for this client.');
        }
        $response_types = explode(' ', $params['response_type']);
        if (count($response_types) > count(array_unique($response_types))) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Invalid "response_type" parameter or parameter is missing.');
        }

        $types = [];
        foreach ($response_types as $response_type) {
            $type = $this->response_types[$response_type];
            $types[] = $type;
        }

        return $types;
    }
}
