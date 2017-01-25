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

namespace OAuth2\Endpoint\Token;

use Interop\Http\Factory\ResponseFactoryInterface;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Command\AccessToken\CreateAccessTokenCommand;
use OAuth2\DataTransporter;
use OAuth2\GrantType\GrantTypeInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Scope\ScopeRepository;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\TokenType\TokenTypeInterface;
use OAuth2\TokenType\TokenTypeManagerInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleBus\Message\Bus\MessageBus;
use Webmozart\Json\JsonEncoder;

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
     * @var ScopeRepository
     */
    private $scopeRepository;

    /**
     * @var JsonEncoder
     */
    private $encoder;

    /**
     * TokenEndpoint constructor.
     *
     * @param ResponseFactoryInterface  $responseFactory
     * @param MessageBus                $commandBus
     * @param TokenTypeManagerInterface $tokenTypeManager
     * @param JsonEncoder               $encoder
     */
    public function __construct(ResponseFactoryInterface $responseFactory, MessageBus $commandBus, TokenTypeManagerInterface $tokenTypeManager, JsonEncoder $encoder)
    {
        $this->responseFactory = $responseFactory;
        $this->commandBus = $commandBus;
        $this->tokenTypeManager = $tokenTypeManager;
        $this->encoder = $encoder;
    }

    /**
     * @param ScopeRepository $scopeRepository
     */
    public function enableScopeSupport(ScopeRepository $scopeRepository)
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
         * @var GrantTypeInterface From the dedicated middleware
         */
        $type = $request->getAttribute('grant_type');

        // Should be created through a static method
        $grantTypeData = new GrantTypeData();
        if (null !== $request->getAttribute('client')) {
            $grantTypeData = $grantTypeData->withClient($request->getAttribute('client'));
        }

        // Type checks the request
        $type->checkTokenRequest($request);

        // Token Response
        $grantTypeData = $type->prepareTokenResponse($request, $grantTypeData);
        if (null === $grantTypeData->getClient()) {
            throw new OAuth2Exception(
                401,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT,
                    'error_description' => 'Client authentication failed.',
                ]
            );
        }

        // This occurs now because the client may be found during the preparation process
        $this->checkGrantType($grantTypeData->getClient(), $type->getGrantType());

        // Populate scope
        // Should check if client is allowed to ask those scopes
        $grantTypeData = $this->populateScope($request, $grantTypeData);

        // Token type parameters
        $grantTypeData = $this->populateTokenTypeInformation($request, $grantTypeData);

        // Grant the access token
        $grantTypeData = $type->grant($request, $grantTypeData);

        $accessToken = $this->issueAccessToken($request, $grantTypeData);

        $response = $this->responseFactory->createResponse();
        $response->getBody()->write($this->encoder->encode($accessToken));
        $headers = ['Content-Type' => 'application/json; charset=UTF-8', 'Cache-Control' => 'no-cache, no-store, max-age=0, must-revalidate, private', 'Pragma' => 'no-cache'];
        foreach ($headers as $k => $v) {
            $response = $response->withHeader($k, $v);
        }

        return $response;
    }

    /**
     * @param ServerRequestInterface $request
     * @param GrantTypeData          $grantTypeData
     *
     * @throws OAuth2Exception
     *
     * @return GrantTypeData
     */
    private function populateTokenTypeInformation(ServerRequestInterface $request, GrantTypeData $grantTypeData): GrantTypeData
    {
        /**
         * @var TokenTypeInterface
         */
        $tokenType = $request->getAttribute('token_type');
        if (!$grantTypeData->getClient()->isTokenTypeAllowed($tokenType->getTokenTypeName())) {
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
            $grantTypeData = $grantTypeData->withParameter($k, $v);
        }

        return $grantTypeData;
    }

    /**
     * @param ServerRequestInterface $request
     * @param GrantTypeData          $grantTypeData
     *
     * @throws OAuth2Exception
     *
     * @return GrantTypeData
     */
    private function populateScope(ServerRequestInterface $request, GrantTypeData $grantTypeData): GrantTypeData
    {
        if (null === $this->scopeRepository) {
            return $grantTypeData;
        }
        $params = $request->getParsedBody() ?? [];
        if (!array_key_exists('scope', $params)) {
            return $grantTypeData;
        }
        $scopeParameter = $params['scope'];
        $scope = $this->scopeRepository->convertToArray($scopeParameter);

        //Modify the scope according to the scope policy
        try {
            $scope = $this->scopeRepository->checkScopePolicy($scope, $grantTypeData->getClient());
        } catch (\InvalidArgumentException $e) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_SCOPE,
                    'error_description' => $e->getMessage(), ]
            );
        }

        $availableScope = is_array($grantTypeData->getAvailableScopes()) ? $grantTypeData->getAvailableScopes() : $this->scopeRepository->getAvailableScopesForClient($grantTypeData->getClient());

        //Check if scope requested are within the available scope
        if (!$this->scopeRepository->areRequestScopesAvailable($scope, $availableScope)) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_SCOPE,
                    'error_description' => sprintf('An unsupported scope was requested. Available scopes are %s.', implode(', ', $availableScope)),
                ]
            );
        }

        $grantTypeData = $grantTypeData->withScopes($scope);

        return $grantTypeData;
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
    private function issueAccessToken(ServerRequestInterface $request, GrantTypeData $grantTypeData)
    {
        return call_user_func($this->callableForNextRule(0), $request, $grantTypeData);
    }

    /**
     * @param int $index
     *
     * @return \Closure
     */
    private function callableForNextRule($index)
    {
        if (!isset($this->tokenEndpointExtensions[$index])) {
            return function (ServerRequestInterface $request, GrantTypeData $grantTypeData) {
                $dataTransporter = new DataTransporter();
                $command = CreateAccessTokenCommand::create(
                    $grantTypeData->getClient()->getId(),
                    $grantTypeData->getResourceOwnerId(),
                    $grantTypeData->getParameters(),
                    $grantTypeData->getMetadatas(),
                    $grantTypeData->getScopes(),
                    new \DateTimeImmutable('now +1 day'),
                    $dataTransporter
                );

                $this->commandBus->handle($command);

                return $dataTransporter->getData();
            };
        }
        $tokenEndpointExtension = $this->tokenEndpointExtensions[$index];

        return function (ServerRequestInterface $request, GrantTypeData $grantTypeData) use ($tokenEndpointExtension, $index) {
            return $tokenEndpointExtension->process($request, $grantTypeData, $this->callableForNextRule($index + 1));
        };
    }
}
