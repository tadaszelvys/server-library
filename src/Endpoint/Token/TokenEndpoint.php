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
use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasClientManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasGrantTypeManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Behaviour\HasTokenEndpointAuthMethodManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Behaviour\HasTokenTypeParameterSupport;
use OAuth2\Behaviour\HasUserAccountManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\GrantTypeManagerInterface;
use OAuth2\Grant\GrantTypeResponse;
use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\TokenType\TokenTypeManagerInterface;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface;
use OAuth2\UserAccount\UserAccountManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenEndpoint implements TokenEndpointInterface
{
    use HasUserAccountManager;
    use HasScopeManager;
    use HasExceptionManager;
    use HasTokenEndpointAuthMethodManager;
    use HasClientManager;
    use HasAccessTokenManager;
    use HasRefreshTokenManager;
    use HasTokenTypeManager;
    use HasTokenTypeParameterSupport;
    use HasGrantTypeManager;

    /**
     * @var \OAuth2\Endpoint\Token\TokenEndpointExtensionInterface[]
     */
    private $token_endpoint_extensions = [];

    /**
     * TokenEndpoint constructor.
     *
     * @param \OAuth2\Grant\GrantTypeManagerInterface                                 $grant_type_manager
     * @param \OAuth2\TokenType\TokenTypeManagerInterface                                 $token_type_manager
     * @param \OAuth2\Token\AccessTokenManagerInterface                               $access_token_manager
     * @param \OAuth2\Client\ClientManagerInterface                                   $client_manager
     * @param \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_manager
     * @param \OAuth2\UserAccount\UserAccountManagerInterface                         $user_account_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                             $exception_manager
     */
    public function __construct(GrantTypeManagerInterface $grant_type_manager, TokenTypeManagerInterface $token_type_manager, AccessTokenManagerInterface $access_token_manager, ClientManagerInterface $client_manager, TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_manager, UserAccountManagerInterface $user_account_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->setTokenTypeManager($token_type_manager);
        $this->setAccessTokenManager($access_token_manager);
        $this->setClientManager($client_manager);
        $this->setTokenEndpointAuthMethodManager($token_endpoint_auth_manager);
        $this->setUserAccountManager($user_account_manager);
        $this->setExceptionManager($exception_manager);
        $this->setGrantTypeManager($grant_type_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function enableRefreshTokenSupport(RefreshTokenManagerInterface $refresh_token_manager)
    {
        $this->setRefreshTokenManager($refresh_token_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function enableScopeSupport(ScopeManagerInterface $scope_manager)
    {
        $this->setScopeManager($scope_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function addTokenEndpointExtension(TokenEndpointExtensionInterface $token_endpoint_extension)
    {
        $this->token_endpoint_extensions[] = $token_endpoint_extension;
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
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_REQUEST, 'The request must be secured.');
        }

        if ('POST' !== $request->getMethod()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_REQUEST, 'Method must be POST.');
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

        if ($this->hasScopeManager()) {
            $this->populateScope($request, $grant_type_response);
        }

        $token_type_information = $this->getTokenTypeInformation($request_parameters, $client);

        $type->grantAccessToken($request, $client, $grant_type_response);

        if ($this->hasScopeManager()) {
            $grant_type_response->setAvailableScope($grant_type_response->getAvailableScope() ?: $this->getScopeManager()->getAvailableScopesForClient($client));

            //Modify the scope according to the scope policy
            try {
                $requested_scope = $this->getScopeManager()->checkScopePolicy($grant_type_response->getRequestedScope(), $client);
            } catch (\InvalidArgumentException $e) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_SCOPE, $e->getMessage());
            }
            $grant_type_response->setRequestedScope($requested_scope);

            //Check if scope requested are within the available scope
            $this->checkRequestedScope($grant_type_response);
        }

        //Call extensions to add metadatas to the Access Token
        $metadatas = $this->preAccessTokenCreation($client, $grant_type_response, $token_type_information);

        //The access token can be created
        $access_token = $this->createAccessToken($client, $grant_type_response, $request_parameters, $token_type_information, $metadatas);

        //The result is processed using the access token and the other information
        $data = $this->postAccessTokenCreation($client, $grant_type_response, $token_type_information, $access_token);

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
     *
     * @return array
     */
    private function preAccessTokenCreation(ClientInterface $client,
                                   GrantTypeResponseInterface $grant_type_response,
                                   array $token_type_information
    ) {
        $metadatas = $grant_type_response->hasAdditionalData('metadatas') ? $grant_type_response->getAdditionalData('metadatas') : [];
        foreach ($this->token_endpoint_extensions as $token_endpoint_extension) {
            $result = $token_endpoint_extension->preAccessTokenCreation(
                $client,
                $grant_type_response,
                $token_type_information
            );

            if (!empty($result)) {
                $metadatas = array_merge($metadatas, $result);
            }
        }

        return $metadatas;
    }

    /**
     * @param \OAuth2\Client\ClientInterface           $client
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     * @param array                                    $token_type_information
     * @param \OAuth2\Token\AccessTokenInterface       $access_token
     *
     * @return array
     */
    private function postAccessTokenCreation(ClientInterface $client,
                                   GrantTypeResponseInterface $grant_type_response,
                                   array $token_type_information,
                                   AccessTokenInterface $access_token
    ) {
        $data = $access_token->toArray();

        foreach ($this->token_endpoint_extensions as $token_endpoint_extension) {
            $result = $token_endpoint_extension->postAccessTokenCreation(
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
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     */
    private function checkRequestedScope(GrantTypeResponseInterface $grant_type_response)
    {
        //Check if scope requested are within the available scope
        if (!$this->getScopeManager()->areRequestScopesAvailable($grant_type_response->getRequestedScope(), $grant_type_response->getAvailableScope())) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_SCOPE, sprintf('An unsupported scope was requested. Available scopes are [%s]', implode(',', $grant_type_response->getAvailableScope())));
        }
    }

    /**
     * @param array                          $request_parameters
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     *
     * @return array
     */
    private function getTokenTypeInformation(array $request_parameters, ClientInterface $client)
    {
        $token_type = $this->getTokenTypeFromRequest($request_parameters);
        if (!$client->isTokenTypeAllowed($token_type->getTokenTypeName())) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_REQUEST, sprintf('The token type "%s" is not allowed for the client.', $token_type->getTokenTypeName()));
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
            $client = $this->getTokenEndpointAuthMethodManager()->findClient($request);
        } else {
            $client_public_id = $grant_type_response->getClientPublicId();
            $client = $this->getClientManager()->getClient($client_public_id);
        }
        if (!$client instanceof ClientInterface) {
            throw $this->getTokenEndpointAuthMethodManager()->buildAuthenticationException($request);
        }

        return $client;
    }

    /**
     * @param \OAuth2\Client\ClientInterface           $client
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     * @param array                                    $request_parameters
     * @param array                                    $token_type_information
     * @param array                                    $metadatas
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Token\AccessTokenInterface
     */
    private function createAccessToken(ClientInterface $client, GrantTypeResponseInterface $grant_type_response, array $request_parameters, array $token_type_information, array $metadatas)
    {
        $refresh_token = null;
        $resource_owner = $this->getResourceOwner(
            $grant_type_response->getResourceOwnerPublicId(),
            $grant_type_response->getUserAccountPublicId()
        );
        if (true === $this->hasRefreshTokenManager()) {
            if (true === $grant_type_response->isRefreshTokenIssued()) {
                $refresh_token = $this->getRefreshTokenManager()->createRefreshToken($client, $resource_owner, $grant_type_response->getRefreshTokenScope(), $metadatas);
            }
        }

        $access_token = $this->getAccessTokenManager()->createAccessToken(
            $client,
            $resource_owner,
            $token_type_information,
            $request_parameters,
            $grant_type_response->getRequestedScope(),
            $refresh_token,
            null, // Resource Server
            $metadatas
        );

        return $access_token;
    }

    /**
     * @param array $request_parameters
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Grant\GrantTypeInterface
     */
    private function getGrantType(array $request_parameters)
    {
        try {
            Assertion::keyExists($request_parameters, 'grant_type', 'The "grant_type" parameter is missing.');
            Assertion::true($this->getGrantTypeManager()->hasGrantType($request_parameters['grant_type']), sprintf('The grant type "%s" is not supported by this server.', $request_parameters['grant_type']));

            return $this->getGrantTypeManager()->getGrantType($request_parameters['grant_type']);
        } catch (\InvalidArgumentException $e) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_REQUEST, $e->getMessage());
        }
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
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_UNAUTHORIZED_CLIENT, sprintf('The grant type "%s" is unauthorized for this client.', $grant_type));
        }
    }

    /**
     * @param string      $resource_owner_public_id
     * @param string|null $user_account_public_id
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return null|\OAuth2\Client\ClientInterface|\OAuth2\UserAccount\UserAccountInterface
     */
    private function getResourceOwner($resource_owner_public_id, $user_account_public_id)
    {
        if (null !== $user_account_public_id) {
            $resource_owner = $this->getUserAccountManager()->getUserAccountByPublicId($user_account_public_id);
        } else {
            $resource_owner = $this->getClientManager()->getClient($resource_owner_public_id);
        }
        if (null === $resource_owner) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::ERROR_INVALID_REQUEST, 'Unable to find resource owner');
        }

        return $resource_owner;
    }
}
