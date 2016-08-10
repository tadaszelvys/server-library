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

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasJWTLoader;
use OAuth2\Behaviour\HasParameterCheckerManager;
use OAuth2\Behaviour\HasResponseModeManager;
use OAuth2\Behaviour\HasResponseTypeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\ResponseTypeManagerInterface;
use OAuth2\ResponseMode\ResponseModeManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationFactory implements AuthorizationFactoryInterface
{
    use HasJWTLoader;
    use HasExceptionManager;
    use HasResponseModeManager;
    use HasResponseTypeManager;
    use HasParameterCheckerManager;

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
     * @param \OAuth2\Endpoint\Authorization\AuthorizationRequestLoaderInterface               $authorization_request_loader
     * @param \OAuth2\Grant\ResponseTypeManagerInterface                                       $response_type_manager
     * @param \OAuth2\ResponseMode\ResponseModeManagerInterface                                $response_mode_manager
     * @param \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface $parameter_checker_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                                      $exception_manager
     */
    public function __construct(
        AuthorizationRequestLoaderInterface $authorization_request_loader,
        ResponseTypeManagerInterface $response_type_manager,
        ResponseModeManagerInterface $response_mode_manager,
        ParameterCheckerManagerInterface $parameter_checker_manager,
        ExceptionManagerInterface $exception_manager
    ) {
        $this->authorization_request_loader = $authorization_request_loader;
        $this->setResponseTypeManager($response_type_manager);
        $this->setResponseModeManager($response_mode_manager);
        $this->setParameterCheckerManager($parameter_checker_manager);
        $this->setExceptionManager($exception_manager);
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
    public function createAuthorizationFromRequest(ServerRequestInterface $request)
    {
        $parameters = $this->authorization_request_loader->loadParametersFromRequest($request);
        $client = $parameters['client'];

        $this->getParameterCheckerManager()->checkParameters($client, $parameters);

        $types = $this->getResponseTypes($parameters);
        $this->checkResponseTypeAllowedForTheClient($client, $parameters);
        $response_mode = $this->getResponseMode($parameters, $types);

        $redirect_uri = $parameters['redirect_uri'];
        $scope = array_key_exists('scope', $parameters) ? $parameters['scope'] : [];

        return new Authorization($parameters, $client, $types, $response_mode, $redirect_uri, $scope);
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode(array $params, array $types)
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
        if (!$this->getResponseModeManager()->hasResponseMode($mode)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, sprintf('Unsupported response mode "%s".', $mode));
        }

        return $this->getResponseModeManager()->getResponseMode($mode);
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $params
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     */
    private function checkResponseTypeAllowedForTheClient(ClientInterface $client, array $params)
    {
        if (!$client->isResponseTypeAllowed($params['response_type'])) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::UNAUTHORIZED_CLIENT, 'The response type "'.$params['response_type'].'" is unauthorized for this client.');
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseTypes(array $params)
    {
        if (!$this->getResponseTypeManager()->isResponseTypeSupported($params['response_type'])) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, sprintf('Response type "%s" is not supported by this server', $params['response_type']));
        }

        try {
            $types = $this->getResponseTypeManager()->getResponseTypes($params['response_type']);
        } catch (\InvalidArgumentException $e) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
        }

        return $types;
    }
}
