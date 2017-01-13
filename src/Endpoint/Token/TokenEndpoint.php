<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Token;

use Interop\Http\Factory\ResponseFactoryInterface;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Command\AccessToken\CreateAccessTokenCommand;
use OAuth2\DataTransporter;
use OAuth2\Grant\GrantTypeInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Scope\ScopeRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\TokenType\TokenTypeInterface;
use OAuth2\TokenType\TokenTypeManagerInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleBus\Message\Bus\MessageBus;

final class TokenEndpoint implements MiddlewareInterface
{
    /**
     * @var ResponseFactoryInterface
     */
    private $responseFactory;

    /**
     * @var TokenEndpointExtensionInterface[]
     */
    private $tokenEndpointExtensions = [];

    /**
     * @var TokenTypeManagerInterface
     */
    private $tokenTypeManager;

    /**
     * @var MessageBus
     */
    private $commandBus;

    /**
     * @var ScopeRepositoryInterface
     */
    private $scopeRepository;

    /**
     * TokenEndpoint constructor.
     * @param ResponseFactoryInterface $responseFactory
     * @param MessageBus $commandBus
     * @param TokenTypeManagerInterface $tokenTypeManager
     */
    public function __construct(ResponseFactoryInterface $responseFactory, MessageBus $commandBus, TokenTypeManagerInterface $tokenTypeManager)
    {
        $this->responseFactory = $responseFactory;
        $this->commandBus = $commandBus;
        $this->tokenTypeManager = $tokenTypeManager;
    }

    /**
     * @param ScopeRepositoryInterface $scopeRepository
     */
    public function enableScopeSupport(ScopeRepositoryInterface $scopeRepository)
    {
        $this->scopeRepository = $scopeRepository;
    }

    /**
     * @param TokenEndpointExtensionInterface $tokenEndpointExtension
     */
    public function addTokenEndpointExtension(TokenEndpointExtensionInterface $tokenEndpointExtension)
    {
        $this->tokenEndpointExtensions[] = $tokenEndpointExtension;
    }

    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        /**
         * @var $type GrantTypeInterface From the dedicated middleware
         */
        $type = $request->getAttribute('grant_type');

        // Should be created through a static method
        $tokenResponse = new GrantTypeResponse();
        if (null !== $request->getAttribute('client')) {
            $tokenResponse = $tokenResponse->withClient($request->getAttribute('client'));
        }

        // Type checks the request
        $type->checkTokenRequest($request);

        // Token Response
        $tokenResponse = $type->prepareTokenResponse($request, $tokenResponse);

        // This occurs now because the client may be found during the preparation process
        $this->checkGrantType($tokenResponse->getClient(), $type->getGrantType());

        // Populate scope
        // Should check if client is allowed to ask those scopes
        $tokenResponse = $this->populateScope($request, $tokenResponse);

        // Token type parameters
        $tokenResponse = $this->populateTokenTypeInformation($request, $tokenResponse);

        // Grant the access token
        $tokenResponse = $type->grant($request, $tokenResponse);

        $accessToken = $this->issueAccessToken($request, $tokenResponse);

        $response = $this->responseFactory->createResponse();
        $response->getBody()->write(json_encode($accessToken));
        $headers = ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store, private', 'Pragma' => 'no-cache'];
        foreach ($headers as $k => $v) {
            $response = $response->withHeader($k, $v);
        }

        return $response;
    }

    /**
     * @param ServerRequestInterface $request
     * @param GrantTypeResponse $tokenResponse
     * @return GrantTypeResponse
     * @throws OAuth2Exception
     */
    private function populateTokenTypeInformation(ServerRequestInterface $request, GrantTypeResponse $tokenResponse): GrantTypeResponse
    {
        /**
         * @var $tokenType TokenTypeInterface
         */
        $tokenType = $request->getAttribute('token_type');
        if (!$tokenResponse->getClient()->isTokenTypeAllowed($tokenType->getTokenTypeName())) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => sprintf('The token type \'%s\' is not allowed for the client.', $tokenType->getTokenTypeName()),
                ]
            );
        }

        $info = $tokenType->getTokenTypeInformation();
        foreach ($info as $k => $v) {
            $tokenResponse = $tokenResponse->withParameter($k, $v);
        }

        return $tokenResponse;
    }

    /**
     * @param ServerRequestInterface     $request
     * @param GrantTypeResponse $tokenResponse
     * @return GrantTypeResponse
     * @throws OAuth2Exception
     */
    private function populateScope(ServerRequestInterface $request, GrantTypeResponse $tokenResponse): GrantTypeResponse
    {
        if (null === $this->scopeRepository) {
            return $tokenResponse;
        }
        $params = $request->getParsedBody();
        if (!array_key_exists('scope', $params)) {
            return $tokenResponse;
        }
        $scopeParameter = $params['scope'];
        $scope = $this->scopeRepository->convertToArray($scopeParameter);

        //Modify the scope according to the scope policy
        try {
            $scope = $this->scopeRepository->checkScopePolicy($scope, $tokenResponse->getClient());
        } catch (\InvalidArgumentException $e) {
            throw new OAuth2Exception(
                400,
                [
                    'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_SCOPE,
                    'error_description' => $e->getMessage()]
            );
        }


        $availableScope = $this->scopeRepository->getAvailableScopesForClient($tokenResponse->getClient());

        //$tokenResponse->setAvailableScope($tokenResponse->getAvailableScope() ?: $this->scopeRepository->getAvailableScopesForClient($tokenResponse->getClient()));


        //Check if scope requested are within the available scope
        if (!$this->scopeRepository->areRequestScopesAvailable($scope, $availableScope)) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_SCOPE,
                    'error_description' => sprintf('An unsupported scope was requested. Available scopes are %s', implode(', ', $availableScope)),
                ]
            );
        }

        $tokenResponse = $tokenResponse->withScopes($scope);

        return $tokenResponse;
    }

    /**
     * @param Client $client
     * @param string $grantType
     *
     * @throws OAuth2Exception
     */
    private function checkGrantType(Client $client, string $grantType)
    {
        if (!$client->isGrantTypeAllowed($grantType)) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_UNAUTHORIZED_CLIENT,
                    'error_description' => sprintf('The grant type \'%s\' is unauthorized for this client.', $grantType),
                ]
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    private function issueAccessToken(ServerRequestInterface $request, GrantTypeResponse $tokenResponse)
    {
        return call_user_func($this->callableForNextRule(0), $request, $tokenResponse);
    }

    /**
     * @param int $index
     *
     * @return \Closure
     */
    private function callableForNextRule($index)
    {
        if (!isset($this->tokenEndpointExtensions[$index])) {
            return function (ServerRequestInterface $request, GrantTypeResponse $tokenResponse) {
                $dataTransporter = new DataTransporter();
                $command = CreateAccessTokenCommand::create(
                    $tokenResponse->getClient(),
                    $tokenResponse->getResourceOwner(),
                    $tokenResponse->getParameters(),
                    $tokenResponse->getMetadatas(),
                    $tokenResponse->getScopes(),
                    $dataTransporter
                );

                $this->commandBus->handle($command);

                return $dataTransporter->getData();
            };
        }
        $tokenEndpointExtension = $this->tokenEndpointExtensions[$index];

        return function (ServerRequestInterface $request, GrantTypeResponse $tokenResponse) use ($tokenEndpointExtension, $index) {
            return $tokenEndpointExtension->process($request, $tokenResponse, $this->callableForNextRule($index + 1));
        };
    }
}
