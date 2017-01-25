<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use OAuth2\Endpoint\Authorization\ParameterChecker\ParameterCheckerManagerInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManager;
use OAuth2\ResponseMode\ResponseModeInterface;
use OAuth2\ResponseMode\ResponseModeManager;
use OAuth2\ResponseType\ResponseTypeManager;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationFactory
{
    /**
     * @var AuthorizationRequestLoader
     */
    private $authorizationRequestLoader;

    /**
     * @var ResponseTypeManager
     */
    private $responseTypeManager;

    /**
     * @var ResponseModeManager
     */
    private $responseModeManager;

    /**
     * @var ParameterCheckerManagerInterface
     */
    private $parameterCheckerManager;

    /**
     * @var bool
     */
    private $responseModeParameterInAuthorizationRequestEnabled = true;

    /**
     * AuthorizationFactory constructor.
     *
     * @param AuthorizationRequestLoader       $authorizationRequestLoader
     * @param ResponseTypeManager     $responseTypeManager
     * @param ResponseModeManager     $responseModeManager
     * @param ParameterCheckerManagerInterface $parameterCheckerManager
     */
    public function __construct(AuthorizationRequestLoader $authorizationRequestLoader, ResponseTypeManager $responseTypeManager, ResponseModeManager $responseModeManager, ParameterCheckerManagerInterface $parameterCheckerManager)
    {
        $this->authorizationRequestLoader = $authorizationRequestLoader;
        $this->responseTypeManager = $responseTypeManager;
        $this->responseModeManager = $responseModeManager;
        $this->parameterCheckerManager = $parameterCheckerManager;
    }

    /**
     * @return bool
     */
    public function isResponseModeParameterSupported(): bool
    {
        return $this->responseModeParameterInAuthorizationRequestEnabled;
    }

    public function enableResponseModeParameterSupport()
    {
        $this->responseModeParameterInAuthorizationRequestEnabled = true;
    }

    public function disableResponseModeParameterSupport()
    {
        $this->responseModeParameterInAuthorizationRequestEnabled = false;
    }

    /**
     * @param ServerRequestInterface $request
     *
     * @return Authorization
     */
    public function createAuthorizationFromRequest(ServerRequestInterface $request): Authorization
    {
        $parameters = $this->authorizationRequestLoader->loadParametersFromRequest($request);
        $client = $parameters['client'];

        $this->parameterCheckerManager->checkParameters($client, $parameters);

        $this->checkResponseTypeAllowedForTheClient($client, $parameters);

        $redirectUri = $parameters['redirect_uri'];
        $scope = array_key_exists('scope', $parameters) ? $parameters['scope'] : [];

        $types = $this->getResponseTypes($parameters);
        $responseMode = $this->getResponseMode($parameters, $types);

        $authorization = new Authorization($parameters, $client, $types, $responseMode, $redirectUri, $scope);

        foreach ($types as $type) {
            $type->checkAuthorization($authorization);
        }

        return $authorization;
    }

    /**
     * @param array $params
     * @param array $types
     *
     * @return ResponseModeInterface
     */
    public function getResponseMode(array $params, array $types): ResponseModeInterface
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
     * @param string $responseType
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return string
     */
    private function getResponseModeIfMultipleResponseTypes($responseType): string
    {
        switch ($responseType) {
            case 'code token':
            case 'code id_token':
            case 'id_token token':
            case 'code id_token token':
                return 'fragment';
            default:
                throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_INVALID_REQUEST, 'error_description' => sprintf('Unsupported response type combination \'%s\'.', $responseType)]);
        }
    }

    /**
     * @param string $mode
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return ResponseModeInterface
     */
    private function getResponseModeService($mode)
    {
        if (!$this->responseModeManager->has($mode)) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_INVALID_REQUEST, 'error_description' => sprintf('Unsupported response mode \'%s\'.', $mode)]);
        }

        return $this->responseModeManager->get($mode);
    }

    /**
     * @param Client $client
     * @param array  $params
     *
     * @throws OAuth2Exception
     */
    private function checkResponseTypeAllowedForTheClient(Client $client, array $params)
    {
        if (!$client->isResponseTypeAllowed($params['response_type'])) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_UNAUTHORIZED_CLIENT, 'error_description' => sprintf('The response type \'%s\' is unauthorized for this client.', $params['response_type'])]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseTypes(array $params)
    {
        if (!$this->responseTypeManager->isSupported($params['response_type'])) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_INVALID_REQUEST, 'error_description' => sprintf('Response type \'%s\' is not supported by this server', $params['response_type'])]);
        }

        try {
            $types = $this->responseTypeManager->find($params['response_type']);
        } catch (\InvalidArgumentException $e) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManager::ERROR_INVALID_REQUEST, 'error_description' => $e->getMessage()]);
        }

        return $types;
    }
}
