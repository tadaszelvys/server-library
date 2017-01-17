<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface;
use OAuth2\Grant\ResponseTypeManagerInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\ResponseMode\ResponseModeManagerInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationFactory implements AuthorizationFactoryInterface
{
    /**
     * @var \OAuth2\Endpoint\Authorization\AuthorizationRequestLoaderInterface
     */
    private $authorizationRequestLoader;

    /**
     * @var bool
     */
    private $responseModeParameterInAuthorizationRequestEnabled = true;

    /**
     * AuthorizationFactory constructor.
     *
     * @param \OAuth2\Endpoint\Authorization\AuthorizationRequestLoaderInterface               $authorizationRequestLoader
     * @param \OAuth2\Grant\ResponseTypeManagerInterface                                       $response_type_manager
     * @param \OAuth2\ResponseMode\ResponseModeManagerInterface                                $response_mode_manager
     * @param \OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface $parameter_checker_manager
     * @param \OAuth2\Response\OAuth2ResponseFactoryManagerInterface                           $response_factory_manager
     */
    public function __construct(AuthorizationRequestLoaderInterface $authorizationRequestLoader, ResponseTypeManagerInterface $response_type_manager, ResponseModeManagerInterface $response_mode_manager, ParameterCheckerManagerInterface $parameter_checker_manager, OAuth2ResponseFactoryManagerInterface $response_factory_manager)
    {
        $this->authorizationRequestLoader = $authorizationRequestLoader;
        $this->setResponseTypeManager($response_type_manager);
        $this->setResponseModeManager($response_mode_manager);
        $this->setParameterCheckerManager($parameter_checker_manager);
        $this->setResponsefactoryManager($response_factory_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function isResponseModeParameterSupported()
    {
        return $this->responseModeParameterInAuthorizationRequestEnabled;
    }

    /**
     * {@inheritdoc}
     */
    public function enableResponseModeParameterSupport()
    {
        $this->responseModeParameterInAuthorizationRequestEnabled = true;
    }

    /**
     * {@inheritdoc}
     */
    public function disableResponseModeParameterSupport()
    {
        $this->responseModeParameterInAuthorizationRequestEnabled = false;
    }

    /**
     * {@inheritdoc}
     */
    public function createAuthorizationFromRequest(ServerRequestInterface $request)
    {
        $parameters = $this->authorizationRequestLoader->loadParametersFromRequest($request);
        $client = $parameters['client'];

        $this->getParameterCheckerManager()->checkParameters($client, $parameters);

        $this->checkResponseTypeAllowedForTheClient($client, $parameters);

        $redirect_uri = $parameters['redirect_uri'];
        $scope = array_key_exists('scope', $parameters) ? $parameters['scope'] : [];

        $types = $this->getResponseTypes($parameters);
        $response_mode = $this->getResponseMode($parameters, $types);

        $authorization = new Authorization($parameters, $client, $types, $response_mode, $redirect_uri, $scope);

        foreach ($types as $type) {
            $type->checkAuthorization($authorization);
        }

        return $authorization;
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
     * @throws \OAuth2\Response\OAuth2Exception
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
                throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => sprintf('Unsupported response type combination \'%s\'.', $response_type)]));
        }
    }

    /**
     * @param string $mode
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return \OAuth2\ResponseMode\ResponseModeInterface
     */
    private function getResponseModeService($mode)
    {
        if (!$this->getResponseModeManager()->hasResponseMode($mode)) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => sprintf('Unsupported response mode \'%s\'.', $mode)]));
        }

        return $this->getResponseModeManager()->getResponseMode($mode);
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $params
     *
     * @throws \OAuth2\Response\OAuth2Exception
     */
    private function checkResponseTypeAllowedForTheClient(ClientInterface $client, array $params)
    {
        if (!$client->isResponseTypeAllowed($params['response_type'])) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_UNAUTHORIZED_CLIENT, 'error_description' => sprintf('The response type \'%s\' is unauthorized for this client.', $params['response_type'])]));
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseTypes(array $params)
    {
        if (!$this->getResponseTypeManager()->isResponseTypeSupported($params['response_type'])) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => sprintf('Response type \'%s\' is not supported by this server', $params['response_type'])]));
        }

        try {
            $types = $this->getResponseTypeManager()->getResponseTypes($params['response_type']);
        } catch (\InvalidArgumentException $e) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => $e->getMessage()]));
        }

        return $types;
    }
}
