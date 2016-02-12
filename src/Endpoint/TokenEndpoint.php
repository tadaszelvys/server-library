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
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasEndUserManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\OpenIDConnect\HasIdTokenManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerSupervisorInterface;
use OAuth2\EndUser\EndUserManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\GrantTypeResponse;
use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Grant\GrantTypeSupportInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\OpenIDConnect\IdTokenManagerInterface;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TokenEndpoint implements TokenEndpointInterface
{
    use HasIdTokenManager;
    use HasEndUserManager;
    use HasScopeManager;
    use HasExceptionManager;
    use HasClientManagerSupervisor;
    use HasAccessTokenManager;
    use HasRefreshTokenManager;
    use HasTokenTypeManager;

    /**
     * @var \OAuth2\Grant\GrantTypeSupportInterface[]
     */
    private $grant_types = [];

    /**
     * @var bool
     */
    private $access_token_type_parameter_allowed = false;

    /**
     * TokenEndpoint constructor.
     *
     * @param \OAuth2\Token\TokenTypeManagerInterface         $token_type_manager
     * @param \OAuth2\Token\AccessTokenManagerInterface       $access_token_manager
     * @param \OAuth2\Client\ClientManagerSupervisorInterface $client_manager_supervisor
     * @param \OAuth2\EndUser\EndUserManagerInterface         $end_user_manager
     * @param \OAuth2\Scope\ScopeManagerInterface             $scope_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     * @param \OAuth2\Token\RefreshTokenManagerInterface|null $refresh_token_manager
     * @param \OAuth2\OpenIDConnect\IdTokenManagerInterface|null      $id_token_manager
     */
    public function __construct(
        TokenTypeManagerInterface $token_type_manager,
        AccessTokenManagerInterface $access_token_manager,
        ClientManagerSupervisorInterface $client_manager_supervisor,
        EndUserManagerInterface $end_user_manager,
        ScopeManagerInterface $scope_manager,
        ExceptionManagerInterface $exception_manager,
        RefreshTokenManagerInterface $refresh_token_manager = null,
        IdTokenManagerInterface $id_token_manager = null
    ) {
        $this->setTokenTypeManager($token_type_manager);
        $this->setAccessTokenManager($access_token_manager);
        $this->setClientManagerSupervisor($client_manager_supervisor);
        $this->setEndUserManager($end_user_manager);
        $this->setScopeManager($scope_manager);
        $this->setExceptionManager($exception_manager);
        if ($id_token_manager instanceof IdTokenManagerInterface) {
            $this->setIdTokenManager($id_token_manager);
        }
        if ($refresh_token_manager instanceof RefreshTokenManagerInterface) {
            $this->setRefreshTokenManager($refresh_token_manager);
        }
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

        return !empty($server_params['HTTPS']) && 'on' === strtolower($server_params['HTTPS']);
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

        if (null === RequestBody::getParameter($request, 'grant_type')) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "grant_type" parameter is missing.');
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
        $grant_type = RequestBody::getParameter($request, 'grant_type');
        $type = $this->getGrantType($grant_type);

        $grant_type_response = new GrantTypeResponse();
        $type->prepareGrantTypeResponse($request, $grant_type_response);

        $client = $this->findClient($request, $grant_type_response);
        $this->checkGrantType($client, $grant_type);

        $grant_type_response->setClientPublicId($client->getPublicId());

        $scope = RequestBody::getParameter($request, 'scope');

        if (null !== $scope) {
            $scope = $this->getScopeManager()->convertToArray($scope);
            $grant_type_response->setRequestedScope($scope);
        }

        $type->grantAccessToken($request, $client, $grant_type_response);

        $grant_type_response->setAvailableScope($grant_type_response->getAvailableScope() ?: $this->getScopeManager()->getAvailableScopesForClient($client));
        $grant_type_response->setRequestedScope($this->getScopeManager()->checkScopePolicy($client, $grant_type_response->getRequestedScope(), $request));

        //Modify the scope according to the scope policy
        //$result['requested_scope'] = $this->getScopeManager()->checkScopePolicy($client, $result['requested_scope'], $request);

        //Check if scope requested are within the available scope
        if (!$this->getScopeManager()->checkScopes($grant_type_response->getRequestedScope(), $grant_type_response->getAvailableScope())) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_SCOPE, 'An unsupported scope was requested. Available scopes are ['.implode(',', $grant_type_response->getAvailableScope()).']');
        }

        $request_parameters = RequestBody::getParameters($request);
        if (true === $this->isAccessTokenTypeParameterAllowed() && array_key_exists('token_type', $request_parameters)) {
            $token_type = $this->getTokenTypeManager()->getTokenType($request_parameters['token_type']);
        } else {
            $token_type = $this->getTokenTypeManager()->getDefaultTokenType();
        }
        $token_type_information = $token_type->getTokenTypeInformation();

        $access_token = $this->createAccessToken(
            $client,
            $grant_type_response,
            $request_parameters,
            $token_type_information
        );

        $data = $access_token->toArray();

        if ($this->getIdTokenManager() instanceof IdTokenManagerInterface && $grant_type_response->isIdTokenIssued()) {
            $id_token = $this->getIdTokenManager()->createIdToken(
                $client,
                $this->getEndUserManager()->getEndUser($grant_type_response->getResourceOwnerPublicId()),
                $token_type_information,
                $grant_type_response->getIdTokenClaims(),
                $access_token,
                $grant_type_response->getAuthorizationCodeToHash()
            );

            $data = array_merge($data, $id_token->toArray());
        }

        $response->getBody()->write(json_encode($data));
        $response = $response->withStatus(200);
        $headers = [
            'Content-Type'  => 'application/json',
            'Cache-Control' => 'no-store, private',
            'Pragma'        => 'no-cache',
        ];
        foreach ($headers as $key => $value) {
            $response = $response->withHeader($key, $value);
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
            $client = $this->getClientManagerSupervisor()->findClient($request);
        } else {
            $client_public_id = $grant_type_response->getClientPublicId();
            $client = $this->getClientManagerSupervisor()->getClient($client_public_id);
        }
        if (!$client instanceof ClientInterface) {
            throw $this->getClientManagerSupervisor()->buildAuthenticationException($request);
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
            $refresh_token
        );

        return $access_token;
    }

    /**
     * @param string $grant_type
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Grant\GrantTypeSupportInterface
     */
    private function getGrantType($grant_type)
    {
        if (array_key_exists($grant_type, $this->grant_types)) {
            return $this->grant_types[$grant_type];
        }
        throw $this->getExceptionManager()->getNotImplementedException(ExceptionManagerInterface::UNSUPPORTED_GRANT_TYPE, 'The grant type "'.$grant_type.'" is not supported by this server');
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param string                         $grant_type
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkGrantType(ClientInterface $client, $grant_type)
    {
        if (!$client->isAllowedGrantType($grant_type)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::UNAUTHORIZED_CLIENT, 'The grant type "'.$grant_type.'" is unauthorized for this client_id');
        }
    }

    /**
     * @param $resource_owner_public_id
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return null|\OAuth2\Client\ClientInterface|\OAuth2\EndUser\EndUserInterface
     */
    private function getResourceOwner($resource_owner_public_id)
    {
        $client = $this->getClientManagerSupervisor()->getClient($resource_owner_public_id);
        if (null !== $client) {
            return $client;
        }
        $end_user = $this->getEndUserManager()->getEndUser($resource_owner_public_id);
        if (null !== $end_user) {
            return $end_user;
        }

        throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Unable to find resource owner');
    }

    public function isAccessTokenTypeParameterAllowed()
    {
        return $this->access_token_type_parameter_allowed;
    }

    /**
     *
     */
    public function allowAccessTokenTypeParameter()
    {
        $this->access_token_type_parameter_allowed = true;
    }

    /**
     *
     */
    public function disallowAccessTokenTypeParameter()
    {
        $this->access_token_type_parameter_allowed = false;
    }
}
