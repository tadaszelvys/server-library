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

use Assert\Assertion;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use OAuth2\Grant\GrantTypeInterface;
use OAuth2\Grant\GrantTypeManagerInterface;
use OAuth2\Grant\GrantTypeResponse;
use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientRepositoryInterface;
use OAuth2\Model\RefreshToken\RefreshTokenRepositoryInterface;
use OAuth2\Model\Scope\ScopeRepositoryInterface;
use OAuth2\Model\UserAccount\UserAccountRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface;
use OAuth2\TokenType\TokenTypeManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

final class TokenEndpoint implements MiddlewareInterface
{
    /**
     * @var TokenEndpointExtensionInterface[]
     */
    private $tokenEndpointExtensions = [];

    /**
     * @var TokenTypeManagerInterface
     */
    private $tokenTypeManager;

    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var TokenEndpointAuthMethodManagerInterface
     */
    private $tokenEndpointAuthManager;

    /**
     * @var UserAccountRepositoryInterface
     */
    private $userAccountRepository;

    /**
     * @var OAuth2ResponseFactoryManagerInterface
     */
    private $responseFactoryManager;

    /**
     * @var GrantTypeManagerInterface
     */
    private $grantTypeManager;

    /**
     * @var ScopeRepositoryInterface
     */
    private $scopeManager;

    /**
     * @var RefreshTokenRepositoryInterface
     */
    private $refreshTokenManager;

    /**
     * TokenEndpoint constructor.
     *
     * @param GrantTypeManagerInterface               $grantTypeManager
     * @param TokenTypeManagerInterface               $tokenTypeManager
     * @param AccessTokenRepositoryInterface          $accessTokenRepository
     * @param TokenEndpointAuthMethodManagerInterface $tokenEndpointAuthManager
     * @param UserAccountRepositoryInterface          $userAccountRepository
     * @param OAuth2ResponseFactoryManagerInterface   $responseFactoryManager
     */
    public function __construct(GrantTypeManagerInterface $grantTypeManager, TokenTypeManagerInterface $tokenTypeManager, AccessTokenRepositoryInterface $accessTokenRepository, ClientRepositoryInterface $clientRepository, TokenEndpointAuthMethodManagerInterface $tokenEndpointAuthManager, UserAccountRepositoryInterface $userAccountRepository, OAuth2ResponseFactoryManagerInterface $responseFactoryManager)
    {
        $this->tokenTypeManager = $tokenTypeManager;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->tokenEndpointAuthManager = $tokenEndpointAuthManager;
        $this->userAccountRepository = $userAccountRepository;
        $this->responseFactoryManager = $responseFactoryManager;
        $this->grantTypeManager = $grantTypeManager;
    }

    /**
     * {@inheritdoc}
     */
    public function enableRefreshTokenSupport(RefreshTokenRepositoryInterface $refreshTokenManager)
    {
        $this->refreshTokenManager = $refreshTokenManager;
    }

    /**
     * {@inheritdoc}
     */
    public function enableScopeSupport(ScopeRepositoryInterface $scopeManager)
    {
        $this->scopeManager = $scopeManager;
    }

    /**
     * {@inheritdoc}
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
        $requestParameters = RequestBody::getParameters($request);
        $type = $this->getGrantType($requestParameters);

        $grantTypeResponse = new GrantTypeResponse();
        $type->prepareGrantTypeResponse($request, $grantTypeResponse);

        $client = $this->findClient($request, $grantTypeResponse);
        $this->checkGrantType($client, $type->getGrantType());

        $grantTypeResponse->setClientPublicId($client->getPublicId());

        if (null !== $this->scopeManager) {
            $this->populateScope($request, $grantTypeResponse);
        }

        $tokenTypeInformation = $this->getTokenTypeInformation($requestParameters, $client);

        $type->grantAccessToken($request, $client, $grantTypeResponse);

        if (null !== $this->scopeManager) {
            $grantTypeResponse->setAvailableScope($grantTypeResponse->getAvailableScope() ?: $this->scopeManager->getAvailableScopesForClient($client));

            //Modify the scope according to the scope policy
            try {
                $requested_scope = $this->scopeManager->checkScopePolicy($grantTypeResponse->getRequestedScope(), $client);
            } catch (\InvalidArgumentException $e) {
                return $this->responseFactoryManager->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_SCOPE, 'error_description' => $e->getMessage()])->getResponse();
            }
            $grantTypeResponse->setRequestedScope($requested_scope);

            //Check if scope requested are within the available scope
            $this->checkRequestedScope($grantTypeResponse);
        }

        //Call extensions to add metadatas to the Access Token
        $metadatas = $this->preAccessTokenCreation($client, $grantTypeResponse, $tokenTypeInformation);

        //The access token can be created
        $accessToken = $this->createAccessToken($client, $grantTypeResponse, $requestParameters, $tokenTypeInformation, $metadatas);

        //The result is processed using the access token and the other information
        $data = $this->postAccessTokenCreation($client, $grantTypeResponse, $tokenTypeInformation, $accessToken);

        //The response is updated
        return $this->responseFactoryManager->getResponse(200, $data)->getResponse();
    }

    /**
     * @param Client                     $client
     * @param GrantTypeResponseInterface $grantTypeResponse
     * @param array                      $tokenTypeInformation
     *
     * @return array
     */
    private function preAccessTokenCreation(Client $client,
                                   GrantTypeResponseInterface $grantTypeResponse,
                                   array $tokenTypeInformation
    ) {
        $metadatas = $grantTypeResponse->hasAdditionalData('metadatas') ? $grantTypeResponse->getAdditionalData('metadatas') : [];
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

        return $metadatas;
    }

    /**
     * @param Client                     $client
     * @param GrantTypeResponseInterface $grantTypeResponse
     * @param array                      $tokenTypeInformation
     * @param AccessTokenInterface       $accessToken
     *
     * @return array
     */
    private function postAccessTokenCreation(Client $client,
                                   GrantTypeResponseInterface $grantTypeResponse,
                                   array $tokenTypeInformation,
                                   AccessTokenInterface $accessToken
    ) {
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
     * @param GrantTypeResponseInterface $grantTypeResponse
     *
     * @throws OAuth2Exception
     */
    private function checkRequestedScope(GrantTypeResponseInterface $grantTypeResponse)
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
     * @param array  $requestParameters
     * @param Client $client
     *
     * @throws OAuth2Exception
     *
     * @return array
     */
    private function getTokenTypeInformation(array $requestParameters, Client $client)
    {
        $token_type = $this->getTokenTypeFromRequest($requestParameters);
        if (!$client->isTokenTypeAllowed($token_type->getTokenTypeName())) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => sprintf('The token type \'%s\' is not allowed for the client.', $token_type->getTokenTypeName()),
                ]
            );
        }

        return $token_type->getTokenTypeInformation();
    }

    /**
     * @param ServerRequestInterface     $request
     * @param GrantTypeResponseInterface $grantTypeResponse
     */
    private function populateScope(ServerRequestInterface $request, GrantTypeResponseInterface &$grantTypeResponse)
    {
        $scope = RequestBody::getParameter($request, 'scope');

        if (null !== $scope) {
            $scope = $this->scopeManager->convertToArray($scope);
            $grantTypeResponse->setRequestedScope($scope);
        }
    }

    /**
     * @param Client                     $client
     * @param GrantTypeResponseInterface $grantTypeResponse
     * @param array                      $requestParameters
     * @param array                      $tokenTypeInformation
     * @param array                      $metadatas
     *
     * @throws OAuth2Exception
     *
     * @return AccessTokenInterface
     */
    private function createAccessToken(Client $client, GrantTypeResponseInterface $grantTypeResponse, array $requestParameters, array $tokenTypeInformation, array $metadatas)
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
     * @param array $requestParameters
     *
     * @throws OAuth2Exception
     *
     * @return GrantTypeInterface
     */
    private function getGrantType(array $requestParameters)
    {
        try {
            Assertion::keyExists($requestParameters, 'grant_type', 'The \'grant_type\' parameter is missing.');
            Assertion::true($this->grantTypeManager->hasGrantType($requestParameters['grant_type']), sprintf('The grant type \'%s\' is not supported by this server.', $requestParameters['grant_type']));

            return $this->grantTypeManager->getGrantType($requestParameters['grant_type']);
        } catch (\InvalidArgumentException $e) {
            throw new OAuth2Exception(400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => $e->getMessage(),
                ]
            );
        }
    }

    /**
     * @param Client $client
     * @param string $grant_type
     *
     * @throws OAuth2Exception
     */
    private function checkGrantType(Client $client, $grant_type)
    {
        if (!$client->isGrantTypeAllowed($grant_type)) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_UNAUTHORIZED_CLIENT,
                    'error_description' => sprintf('The grant type \'%s\' is unauthorized for this client.', $grant_type),
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
}
