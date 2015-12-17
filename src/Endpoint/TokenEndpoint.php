<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint;

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasAccessTokenTypeManager;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasEndUserManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerSupervisorInterface;
use OAuth2\EndUser\EndUserManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\GrantTypeResponse;
use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Grant\GrantTypeSupportInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\AccessTokenTypeManagerInterface;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TokenEndpoint implements TokenEndpointInterface
{
    use HasEndUserManager;
    use HasAccessTokenTypeManager;
    use HasScopeManager;
    use HasExceptionManager;
    use HasClientManagerSupervisor;
    use HasAccessTokenManager;
    use HasRefreshTokenManager;

    /**
     * @var \OAuth2\Grant\GrantTypeSupportInterface[]
     */
    protected $grant_types = [];

    /**
     * TokenEndpoint constructor.
     *
     * @param \OAuth2\Token\AccessTokenManagerInterface       $access_token_manager
     * @param \OAuth2\Token\AccessTokenTypeManagerInterface   $access_token_type_manager
     * @param \OAuth2\Token\RefreshTokenManagerInterface      $refresh_token_manager
     * @param \OAuth2\Client\ClientManagerSupervisorInterface $client_manager_supervisor
     * @param \OAuth2\EndUser\EndUserManagerInterface         $end_user_manager
     * @param \OAuth2\Scope\ScopeManagerInterface             $scope_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     */
    public function __construct(
        AccessTokenManagerInterface $access_token_manager,
        AccessTokenTypeManagerInterface $access_token_type_manager,
        RefreshTokenManagerInterface $refresh_token_manager,
        ClientManagerSupervisorInterface $client_manager_supervisor,
        EndUserManagerInterface $end_user_manager,
        ScopeManagerInterface $scope_manager,
        ExceptionManagerInterface $exception_manager
    ) {
        $this->setAccessTokenManager($access_token_manager);
        $this->setAccessTokenTypeManager($access_token_type_manager);
        $this->setRefreshTokenManager($refresh_token_manager);
        $this->setClientManagerSupervisor($client_manager_supervisor);
        $this->setEndUserManager($end_user_manager);
        $this->setScopeManager($scope_manager);
        $this->setExceptionManager($exception_manager);
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
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return bool
     */
    private function isRequestSecured(ServerRequestInterface $request)
    {
        $server_params = $request->getServerParams();

        return !empty($server_params['HTTPS']) && 'off' !== strtolower($server_params['HTTPS']);
    }

    /**
     * {@inheritdoc}
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     * @throws \OAuth2\Exception\NotImplementedExceptionInterface
     */
    public function getAccessToken(ServerRequestInterface $request, ResponseInterface &$response)
    {
        if (!$this->isRequestSecured($request)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The request must be secured.');
        }

        if ('POST' !== $request->getMethod()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Method must be POST.');
        }

        if (null === RequestBody::getParameter($request, 'grant_type')) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "grant_type" parameter is missing.');
        }

        $this->handleRequest($request, $response);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface      $response
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function handleRequest(ServerRequestInterface $request, ResponseInterface &$response)
    {
        $grant_type = RequestBody::getParameter($request, 'grant_type');
        $type = $this->getGrantType($grant_type);

        $grant_type_response = new GrantTypeResponse();
        $type->prepareGrantTypeResponse($request, $grant_type_response);

        $client = $this->findClient($request, $grant_type_response);
        $this->checkGrantType($client, $grant_type);

        $grant_type_response->setClientPublicId($client->getPublicId());

        $type->grantAccessToken($request, $client, $grant_type_response);

        $result = [
            'requested_scope'          => $grant_type_response->getRequestedScope() ?: $this->getScopeManager()->getDefaultScopes($client),
            'available_scope'          => $grant_type_response->getAvailableScope() ?: $this->getScopeManager()->getAvailableScopes($client),
            'resource_owner_public_id' => $grant_type_response->getResourceOwnerPublicid(),
            'refresh_token'            => [
                'issued' => $grant_type_response->isRefreshTokenIssued(),
                'scope'  => $grant_type_response->getRefreshTokenScope(),
                'used'   => $grant_type_response->getRefreshTokenRevoked(),
            ],
        ];

        foreach (['requested_scope', 'available_scope'] as $key) {
            $result[$key] = $this->getScopeManager()->convertToScope($result[$key]);
        }

        //Modify the scope according to the scope policy
        $result['requested_scope'] = $this->getScopeManager()->checkScopePolicy($client, $result['requested_scope'], $request);

        //Check if scope requested are within the available scope
        if (!$this->getScopeManager()->checkScopes($result['requested_scope'], $result['available_scope'])) {
            throw $this->getExceptionManager()->getException('BadRequest', 'invalid_scope', 'An unsupported scope was requested. Available scopes are ['.implode(',', $result['available_scope']).']');
        }

        //Create and return access token (with refresh token and other information if asked) as an array
        $token = $this->createAccessToken($client, $result);

        $prepared = $this->getAccessTokenTypeManager()->getDefaultAccessTokenType()->prepareAccessToken($token);

        $response->getBody()->write(json_encode($prepared));
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
    protected function findClient(ServerRequestInterface $request, GrantTypeResponseInterface $grant_type_response)
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
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $values
     *
     * @return \OAuth2\Token\AccessTokenInterface
     */
    protected function createAccessToken(ClientInterface $client, array $values)
    {
        $refresh_token = null;
        $resource_owner = $this->getResourceOwner($values['resource_owner_public_id']);
        if (null !== $this->getRefreshTokenManager()) {
            if (true === $values['refresh_token']['issued']) {
                $values['refresh_token']['scope'] = $this->getScopeManager()->convertToScope($values['refresh_token']['scope']);
                $refresh_token = $this->getRefreshTokenManager()->createRefreshToken($client, $resource_owner, $values['refresh_token']['scope']);
            }
            if ($values['refresh_token']['used'] instanceof RefreshTokenInterface) {
                $this->getRefreshTokenManager()->markRefreshTokenAsUsed($values['refresh_token']['used']);
            }
        }

        $access_token = $this->getAccessTokenManager()->createAccessToken($client, $resource_owner, $values['requested_scope'], $refresh_token);

        return $access_token;
    }

    /**
     * @param string $grant_type
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Grant\GrantTypeSupportInterface
     */
    protected function getGrantType($grant_type)
    {
        if (array_key_exists($grant_type, $this->grant_types)) {
            return $this->grant_types[$grant_type];
        }
        throw $this->getExceptionManager()->getException(ExceptionManagerInterface::NOT_IMPLEMENTED, ExceptionManagerInterface::UNSUPPORTED_GRANT_TYPE, 'The grant type "'.$grant_type.'" is not supported by this server');
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param string                         $grant_type
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    protected function checkGrantType(ClientInterface $client, $grant_type)
    {
        if (!$client->isAllowedGrantType($grant_type)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::UNAUTHORIZED_CLIENT, 'The grant type "'.$grant_type.'" is unauthorized for this client_id');
        }
    }

    /**
     * @param $resource_owner_public_id
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return null|\OAuth2\Client\ClientInterface|\OAuth2\EndUser\EndUserInterface
     */
    protected function getResourceOwner($resource_owner_public_id)
    {
        $client = $this->getClientManagerSupervisor()->getClient($resource_owner_public_id);
        if (null !== $client) {
            return $client;
        }
        $end_user = $this->getEndUserManager()->getEndUser($resource_owner_public_id);
        if (null !== $end_user) {
            return $end_user;
        }

        throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Unable to find resource owner');
    }
}
