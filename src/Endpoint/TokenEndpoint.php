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

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasClientManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Behaviour\HasTokenTypeParameterSupport;
use OAuth2\Behaviour\HasUserManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\GrantTypeResponse;
use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Grant\GrantTypeSupportInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;
use OAuth2\User\UserManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TokenEndpoint implements TokenEndpointInterface
{
    use HasUserManager;
    use HasScopeManager;
    use HasExceptionManager;
    use HasClientManager;
    use HasAccessTokenManager;
    use HasRefreshTokenManager;
    use HasTokenTypeManager;
    use HasTokenTypeParameterSupport;

    /**
     * @var \OAuth2\Grant\GrantTypeSupportInterface[]
     */
    private $grant_types = [];

    /**
     * @var \OAuth2\Endpoint\TokenEndpointExtensionInterface[]
     */
    private $token_endpoint_extensions = [];

    /**
     * TokenEndpoint constructor.
     *
     * @param \OAuth2\Token\TokenTypeManagerInterface         $token_type_manager
     * @param \OAuth2\Token\AccessTokenManagerInterface       $access_token_manager
     * @param \OAuth2\Client\ClientManagerInterface $client_manager
     * @param \OAuth2\User\UserManagerInterface               $user_manager
     * @param \OAuth2\Scope\ScopeManagerInterface             $scope_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     * @param \OAuth2\Token\RefreshTokenManagerInterface|null $refresh_token_manager
     */
    public function __construct(
        TokenTypeManagerInterface $token_type_manager,
        AccessTokenManagerInterface $access_token_manager,
        ClientManagerInterface $client_manager,
        UserManagerInterface $user_manager,
        ScopeManagerInterface $scope_manager,
        ExceptionManagerInterface $exception_manager,
        RefreshTokenManagerInterface $refresh_token_manager = null
    ) {
        $this->setTokenTypeManager($token_type_manager);
        $this->setAccessTokenManager($access_token_manager);
        $this->setClientManager($client_manager);
        $this->setUserManager($user_manager);
        $this->setScopeManager($scope_manager);
        $this->setExceptionManager($exception_manager);
        if ($refresh_token_manager instanceof RefreshTokenManagerInterface) {
            $this->setRefreshTokenManager($refresh_token_manager);
        }
    }

    /**
     * @param \OAuth2\Endpoint\TokenEndpointExtensionInterface $token_endpoint_extension
     */
    public function addTokenEndpointExtension(TokenEndpointExtensionInterface $token_endpoint_extension)
    {
        $this->token_endpoint_extensions[] = $token_endpoint_extension;
    }

    /**
     * @param \OAuth2\Grant\GrantTypeSupportInterface $grant_type
     */
    public function addGrantType(GrantTypeSupportInterface $grant_type)
    {
        $type = $grant_type->getGrantType();
        if (!array_key_exists($type, $this->grant_types)) {
            $this->grant_types[$type] = $grant_type;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantTypesSupported()
    {
        return array_keys($this->grant_types);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool
     */
    private function isRequestSecured(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();

        return !empty($server_params['HTTPS']) && 'on' === mb_strtolower($server_params['HTTPS'], '8bit');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken(ServerRequestInterface $request, ResponseInterface &$response)
    {
        if (!$this->isRequestSecured($request)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The request must be secured.');
        }

        if ('POST' !== $request->getMethod()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Method must be POST.');
        }

        $this->handleRequest($request, $response);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function handleRequest(ServerRequestInterface $request, ResponseInterface &$response)
    {
        $request_parameters = RequestBody::getParameters($request);
        $type = $this->getGrantType($request_parameters);

        $grant_type_response = new GrantTypeResponse();
        $type->prepareGrantTypeResponse($request, $grant_type_response);

        $client = $this->findClient($request, $grant_type_response);
        $this->checkGrantType($client, $type->getGrantType());

        $grant_type_response->setClientPublicId($client->getPublicId());

        $this->populateScope($request, $grant_type_response);

        $token_type_information = $this->getTokenTypeInformation($request_parameters, $client);

        $type->grantAccessToken($request, $client, $grant_type_response);

        $grant_type_response->setAvailableScope($grant_type_response->getAvailableScope() ?: $this->getScopeManager()->getAvailableScopesForClient($client));

        //Modify the scope according to the scope policy
        $grant_type_response->setRequestedScope($this->getScopeManager()->checkScopePolicy($grant_type_response->getRequestedScope(), $client));

        //Check if scope requested are within the available scope
        $this->checkRequestedScope($grant_type_response);

        //The access token can be created
        $access_token = $this->createAccessToken(
            $client,
            $grant_type_response,
            $request_parameters,
            $token_type_information
        );

        //The result is processed using the access token and the other information
        $data = $this->processResult(
            $client,
            $grant_type_response,
            $token_type_information,
            $access_token
        );

        //The response is updated
        $this->processResponse($response, $data);
    }

    /**
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param array                               $data
     */
    private function processResponse(ResponseInterface &$response, array $data)
    {
        $response->getBody()->write(json_encode($data));
        $headers = [
            'Content-Type'  => 'application/json',
            'Cache-Control' => 'no-store, private',
            'Pragma'        => 'no-cache',
        ];
        foreach ($headers as $key => $value) {
            $response = $response->withHeader($key, $value);
        }
        $response = $response->withStatus(200);
    }

    /**
     * @param \OAuth2\Client\ClientInterface           $client
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     * @param array                                    $token_type_information
     * @param \OAuth2\Token\AccessTokenInterface       $access_token
     *
     * @return array
     */
    private function processResult(ClientInterface $client,
                                   GrantTypeResponseInterface $grant_type_response,
                                   array $token_type_information,
                                   AccessTokenInterface $access_token
    ) {
        $data = $access_token->toArray();

        foreach ($this->token_endpoint_extensions as $token_endpoint_extension) {
            $result = $token_endpoint_extension->process(
                $client,
                $grant_type_response,
                $token_type_information,
                $access_token
            );

            if (!empty($result)) {
                $data = array_merge($data, $result);
            }
        }

        return $data;
    }

    /**
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     */
    private function checkRequestedScope(GrantTypeResponseInterface $grant_type_response)
    {
        //Check if scope requested are within the available scope
        if (!$this->getScopeManager()->checkScopes($grant_type_response->getRequestedScope(), $grant_type_response->getAvailableScope())) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_SCOPE, sprintf('An unsupported scope was requested. Available scopes are [%s]', implode(',', $grant_type_response->getAvailableScope())));
        }
    }

    /**
     * @param array                          $request_parameters
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @return array
     */
    private function getTokenTypeInformation(array $request_parameters, ClientInterface $client)
    {
        $token_type = $this->getTokenTypeFromRequest($request_parameters);
        if (!$client->isTokenTypeAllowed($token_type->getTokenTypeName())) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, sprintf('The token type "%s" is not allowed for the client.', $token_type->getTokenTypeName()));
        }

        return $token_type->getTokenTypeInformation();
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     */
    private function populateScope(ServerRequestInterface $request, GrantTypeResponseInterface &$grant_type_response)
    {
        $scope = RequestBody::getParameter($request, 'scope');

        if (null !== $scope) {
            $scope = $this->getScopeManager()->convertToArray($scope);
            $grant_type_response->setRequestedScope($scope);
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Client\ClientInterface
     */
    private function findClient(ServerRequestInterface $request, GrantTypeResponseInterface $grant_type_response)
    {
        if (null === $grant_type_response->getClientPublicId()) {
            $client = $this->getClientManager()->findClient($request);
        } else {
            $client_public_id = $grant_type_response->getClientPublicId();
            $client = $this->getClientManager()->getClient($client_public_id);
        }
        if (!$client instanceof ClientInterface) {
            throw $this->getClientManager()->buildAuthenticationException($request);
        }

        return $client;
    }

    /**
     * @param \OAuth2\Client\ClientInterface           $client
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     * @param array                                    $request_parameters
     * @param array                                    $token_type_information
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Token\AccessTokenInterface
     */
    private function createAccessToken(ClientInterface $client, GrantTypeResponseInterface $grant_type_response, array $request_parameters, array $token_type_information)
    {
        $refresh_token = null;
        $resource_owner = $this->getResourceOwner($grant_type_response->getResourceOwnerPublicId());
        if (null !== $this->getRefreshTokenManager()) {
            if (true === $grant_type_response->isRefreshTokenIssued()) {
                $refresh_token = $this->getRefreshTokenManager()->createRefreshToken($client, $resource_owner, $grant_type_response->getRefreshTokenScope());
            }
            if ($grant_type_response->getRefreshTokenRevoked() instanceof RefreshTokenInterface) {
                $this->getRefreshTokenManager()->markRefreshTokenAsUsed($grant_type_response->getRefreshTokenRevoked());
            }
        }

        $access_token = $this->getAccessTokenManager()->createAccessToken(
            $client,
            $resource_owner,
            $token_type_information,
            $request_parameters,
            $grant_type_response->getRequestedScope(),
            $refresh_token,
            null,
            $grant_type_response->getRedirectUri()
        );

        return $access_token;
    }

    /**
     * @param array $request_parameters
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Grant\GrantTypeSupportInterface
     */
    private function getGrantType(array $request_parameters)
    {
        foreach ($this->grant_types as $grant_type) {
            if ($grant_type->isSupported($request_parameters)) {
                return $grant_type;
            }
        }
        throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Invalid or unsupported request.');
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param string                         $grant_type
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkGrantType(ClientInterface $client, $grant_type)
    {
        if (!$client->isGrantTypeAllowed($grant_type)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::UNAUTHORIZED_CLIENT, sprintf('The grant type "%s" is unauthorized for this client.', $grant_type));
        }
    }

    /**
     * @param string $resource_owner_public_id
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return null|\OAuth2\Client\ClientInterface|\OAuth2\User\UserInterface
     */
    private function getResourceOwner($resource_owner_public_id)
    {
        $client = $this->getClientManager()->getClient($resource_owner_public_id);
        if (null !== $client) {
            return $client;
        }
        $user = $this->getUserManager()->getUser($resource_owner_public_id);
        if (null !== $user) {
            return $user;
        }

        throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Unable to find resource owner');
    }
}
