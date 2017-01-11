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
use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\Client\Client;
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
         * @var $type GrantTypeInterface
         */
        $type = $request->getAttribute('grant_type');

        $grantTypeResponse = new GrantTypeResponse();
        if (null !== $request->getAttribute('client')) {
            $grantTypeResponse = $grantTypeResponse->withClient($request->getAttribute('client'));
        }
        $type->prepareGrantTypeResponse($request, $grantTypeResponse);
        $this->checkGrantType($grantTypeResponse->getClient(), $type->getGrantType());

        //$grantTypeResponse->setClientPublicId($client->getPublicId());

        /*if (null !== $this->scopeManager) {
            $this->populateScope($request, $grantTypeResponse);
        }*/

        $this->populateTokenTypeInformation($request, $grantTypeResponse);
        $type->grantAccessToken($request, $grantTypeResponse->getClient(), $grantTypeResponse);

        /*if (null !== $this->scopeManager) {
            $grantTypeResponse->setAvailableScope($grantTypeResponse->getAvailableScope() ?: $this->scopeManager->getAvailableScopesForClient($grantTypeResponse->getClient()));

            //Modify the scope according to the scope policy
            try {
                $requested_scope = $this->scopeManager->checkScopePolicy($grantTypeResponse->getRequestedScope(), $grantTypeResponse->getClient());
            } catch (\InvalidArgumentException $e) {
                return $this->responseFactoryManager->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_SCOPE, 'error_description' => $e->getMessage()])->getResponse();
            }
            $grantTypeResponse->setRequestedScope($requested_scope);

            //Check if scope requested are within the available scope
            $this->checkRequestedScope($grantTypeResponse);
        }*/

        //Call extensions to add metadatas to the Access Token
        //$metadatas = $this->preAccessTokenCreation($grantTypeResponse->getClient(), $grantTypeResponse, $tokenTypeInformation);

        //The access token can be created
        $dataTransporter = new DataTransporter();
        $command = CreateAccessTokenCommand::create(
            $grantTypeResponse->getClient(),
            $grantTypeResponse->getResourceOwner(),
            $grantTypeResponse->getParameters(),
            $grantTypeResponse->getMetadatas(),
            $grantTypeResponse->getScopes(),
            $dataTransporter
        );

        $this->commandBus->handle($command);
        $data = $dataTransporter->getData();
        //$accessToken = $this->createAccessToken($grantTypeResponse->getClient(), $grantTypeResponse, $requestParameters, $tokenTypeInformation, $metadatas);

        //The result is processed using the access token and the other information
        //$data = $this->postAccessTokenCreation($grantTypeResponse, $tokenTypeInformation, $dataTransporter->getData());

        $response = $this->responseFactory->createResponse();
        $response->getBody()->write(json_encode($data));
dump(json_encode($data));
        return $response;
        //The response is updated
        //return $this->responseFactoryManager->getResponse(200, $data)->getResponse();
    }

    /**
     * @param Client                     $client
     * @param GrantTypeResponse $grantTypeResponse
     * @param array                      $tokenTypeInformation
     *
     * @return array
     */
    private function preAccessTokenCreation(Client $client, GrantTypeResponse $grantTypeResponse, array $tokenTypeInformation)
    {
        /*$metadatas = $grantTypeResponse->hasData('metadatas') ? $grantTypeResponse->getData('metadatas') : [];
        foreach ($this->tokenEndpointExtensions as $tokenEndpointExtension) {
            $result = $tokenEndpointExtension->preAccessTokenCreation(
                $client,
                $grantTypeResponse,
                $tokenTypeInformation
            );

            if (!empty($result)) {
                $metadatas = array_merge($metadatas, $result);
            }
        }

        return $metadatas;*/
    }

    /**
     * @param GrantTypeResponse $grantTypeResponse
     * @param array             $tokenTypeInformation
     * @param AccessToken       $accessToken
     *
     * @return array
     */
    private function postAccessTokenCreation(GrantTypeResponse $grantTypeResponse, array $tokenTypeInformation, AccessToken $accessToken)
    {
        $data = $accessToken->toArray();

        foreach ($this->tokenEndpointExtensions as $tokenEndpointExtension) {
            $result = $tokenEndpointExtension->postAccessTokenCreation(
                $client,
                $grantTypeResponse,
                $tokenTypeInformation,
                $accessToken
            );

            if (!empty($result)) {
                $data = array_merge($data, $result);
            }
        }

        return $data;
    }

    /**
     * @param GrantTypeResponse $grantTypeResponse
     *
     * @throws OAuth2Exception
     */
    private function checkRequestedScope(GrantTypeResponse $grantTypeResponse)
    {
        //Check if scope requested are within the available scope
        if (!$this->scopeManager->areRequestScopesAvailable($grantTypeResponse->getRequestedScope(), $grantTypeResponse->getAvailableScope())) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_SCOPE,
                    'error_description' => sprintf('An unsupported scope was requested. Available scopes are [%s]', implode(',', $grantTypeResponse->getAvailableScope())),
                ]
            );
        }
    }

    /**
     * @param ServerRequestInterface $request
     * @param GrantTypeResponse $grantTypeResponse
     * @return array
     * @throws OAuth2Exception
     */
    private function populateTokenTypeInformation(ServerRequestInterface $request, GrantTypeResponse &$grantTypeResponse)
    {
        /**
         * @var $tokenType TokenTypeInterface
         */
        $tokenType = $request->getAttribute('token_type');
        if (!$grantTypeResponse->getClient()->isTokenTypeAllowed($tokenType->getTokenTypeName())) {
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
            $grantTypeResponse = $grantTypeResponse->withParameter($k, $v);
        }
    }

    /**
     * @param ServerRequestInterface     $request
     * @param GrantTypeResponse $grantTypeResponse
     */
    private function populateScope(ServerRequestInterface $request, GrantTypeResponse &$grantTypeResponse)
    {
        $scope = RequestBody::getParameter($request, 'scope');

        if (null !== $scope) {
            $scope = $this->scopeManager->convertToArray($scope);
            $grantTypeResponse->setRequestedScope($scope);
        }
    }

    /**
     * @param Client                     $client
     * @param GrantTypeResponse $grantTypeResponse
     * @param array                      $requestParameters
     * @param array                      $tokenTypeInformation
     * @param array                      $metadatas
     *
     * @throws OAuth2Exception
     *
     * @return AccessToken
     */
    private function createAccessToken(Client $client, GrantTypeResponse $grantTypeResponse, array $requestParameters, array $tokenTypeInformation, array $metadatas)
    {
        $refresh_token = null;
        $resourceOwner = $this->getResourceOwner(
            $grantTypeResponse->getResourceOwnerPublicId(),
            $grantTypeResponse->getUserAccountPublicId()
        );
        if (null !== $this->refreshTokenManager) {
            if (true === $grantTypeResponse->isRefreshTokenIssued()) {
                $refresh_token = $this->refreshTokenManager->createRefreshToken($client, $resourceOwner, $grantTypeResponse->getRefreshTokenScope(), $metadatas);
            }
        }

        $accessToken = $this->accessTokenRepository->createAccessToken(
            $client,
            $resourceOwner,
            $tokenTypeInformation,
            $requestParameters,
            $grantTypeResponse->getRequestedScope(),
            $refresh_token,
            null, // Resource Server
            $metadatas
        );

        return $accessToken;
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
     * @param string      $resourceOwner_public_id
     * @param string|null $user_account_public_id
     *
     * @throws OAuth2Exception
     *
     * @return null|Client|UserAccountInterface
     */
    private function getResourceOwner($resourceOwner_public_id, $user_account_public_id)
    {
        if (null !== $user_account_public_id) {
            $resourceOwner = $this->userAccountRepository->getUserAccountByPublicId($user_account_public_id);
        } else {
            $resourceOwner = $this->clientManager->getClient($resourceOwner_public_id);
        }
        if (null === $resourceOwner) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => 'Unable to find resource owner',
                ]
            );
        }

        return $resourceOwner;
    }

    /**
     * Appends new middleware for this message bus. Should only be used at configuration time.
     *
     * @private
     *
     * @param TokenEndpointExtensionInterface $tokenEndpointExtension
     *
     * @return self
     */
    public function appendTokenEndpointExtension(TokenEndpointExtensionInterface $tokenEndpointExtension)
    {
        $this->tokenEndpointExtensions[] = $tokenEndpointExtension;

        return $this;
    }

    /**
     * @return TokenEndpointExtensionInterface[]
     */
    public function getTokenEndpointExtensions()
    {
        return $this->tokenEndpointExtensions;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(ServerRequestInterface $serverRequest)
    {
        return call_user_func($this->callableForNextTokenEndpointExtension(0), $serverRequest, []);
    }

    /**
     * @param int $index
     *
     * @return \Closure
     */
    private function callableForNextTokenEndpointExtension($index)
    {
        if (!isset($this->tokenEndpointExtensions[$index])) {
            return function (ServerRequestInterface $serverRequest, array $data) {
                return $data;
            };
        }
        $tokenEndpointExtension = $this->tokenEndpointExtensions[$index];

        return function (ServerRequestInterface $serverRequest, array $data) use ($tokenEndpointExtension, $index) {
            return $tokenEndpointExtension->handle($serverRequest, $data, $this->callableForNextTokenEndpointExtension($index + 1));
        };
    }
}
