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

use Base64Url\Base64Url;
use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasClientManagerSupervisor;
use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasEndUserManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasIdTokenManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManagerSupervisorInterface;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\EndUser\EndUserManagerInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\GrantTypeResponse;
use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Grant\GrantTypeSupportInterface;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\IdTokenManagerInterface;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TokenEndpoint implements TokenEndpointInterface
{
    use HasConfiguration;
    use HasIdTokenManager;
    use HasEndUserManager;
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
     * @param \OAuth2\Token\IdTokenManagerInterface           $id_token_manager
     * @param \OAuth2\Token\AccessTokenManagerInterface       $access_token_manager
     * @param \OAuth2\Client\ClientManagerSupervisorInterface $client_manager_supervisor
     * @param \OAuth2\EndUser\EndUserManagerInterface         $end_user_manager
     * @param \OAuth2\Scope\ScopeManagerInterface             $scope_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface     $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface    $configuration
     * @param \OAuth2\Token\RefreshTokenManagerInterface|null $refresh_token_manager
     */
    public function __construct(
        IdTokenManagerInterface $id_token_manager,
        AccessTokenManagerInterface $access_token_manager,
        ClientManagerSupervisorInterface $client_manager_supervisor,
        EndUserManagerInterface $end_user_manager,
        ScopeManagerInterface $scope_manager,
        ExceptionManagerInterface $exception_manager,
        ConfigurationInterface $configuration,
        RefreshTokenManagerInterface $refresh_token_manager = null
    ) {
        $this->setIdTokenManager($id_token_manager);
        $this->setAccessTokenManager($access_token_manager);
        $this->setClientManagerSupervisor($client_manager_supervisor);
        $this->setEndUserManager($end_user_manager);
        $this->setScopeManager($scope_manager);
        $this->setExceptionManager($exception_manager);
        $this->setConfiguration($configuration);
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
    private function handleRequest(ServerRequestInterface $request, ResponseInterface &$response)
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
            'id_token'                 => [
                'issued'    => $grant_type_response->isIdTokenIssued(),
                'auth_code' => $grant_type_response->getAuthorizationCodeToHash(),
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
        $access_token = $this->createAccessToken($client, $result, RequestBody::getParameters($request));
        $token = $access_token->toArray();
        if (true === $grant_type_response->isIdTokenIssued()) {
            $id_token = $this->createIdToken($access_token, $client, $result);
            $token['id_token'] = $id_token->getToken();
        }

        $response->getBody()->write(json_encode($token));
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
     * @param \OAuth2\Token\AccessTokenInterface $access_token
     * @param \OAuth2\Client\ClientInterface     $client
     * @param array                              $values
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return \OAuth2\Token\IdTokenInterface
     */
    private function createIdToken(AccessTokenInterface $access_token, ClientInterface $client, array $values)
    {
        $signature_algorithm = $this->getConfiguration()->get('id_token_signature_algorithm', null);
        $resource_owner = $this->getEndUserManager()->getEndUser($values['resource_owner_public_id']);

        if (!$resource_owner instanceof EndUserInterface) {
            throw $this->getExceptionManager()->getException(
                ExceptionManagerInterface::INTERNAL_SERVER_ERROR,
                'bad_grant_type_implementation',
                'The server tried to get the resource owner associated with the Id Token, but the resource owner does not exist.'
            );
        }

        if (null !== $values['id_token']['auth_code']) {
            $c_hash = substr(
                Base64Url::encode(hash(
                    $this->getAtHashMethod($signature_algorithm),
                    $values['id_token']['auth_code'],
                    true
                )),
                0,
                $this->getAtHashSize($signature_algorithm)
            );
        } else {
            $c_hash = null;
        }

        $at_hash = substr(
            Base64Url::encode(hash(
                $this->getAtHashMethod($signature_algorithm),
                $access_token->getToken(),
                true
            )),
            0,
            $this->getAtHashSize($signature_algorithm)
        );

        return $this->getIdTokenManager()->createIdToken(
            $client,
            $resource_owner,
            $at_hash,
            $c_hash
        );
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $values
     * @param array                          $request_parameters
     *
     * @return \OAuth2\Token\AccessTokenInterface
     */
    private function createAccessToken(ClientInterface $client, array $values, array $request_parameters)
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

        $access_token = $this->getAccessTokenManager()->createAccessToken($client, $resource_owner, $request_parameters, $values['requested_scope'], $refresh_token);

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
        throw $this->getExceptionManager()->getException(ExceptionManagerInterface::NOT_IMPLEMENTED, ExceptionManagerInterface::UNSUPPORTED_GRANT_TYPE, 'The grant type "'.$grant_type.'" is not supported by this server');
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

        throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Unable to find resource owner');
    }

    private function getAtHashMethod($id_token_signature_alogrithm)
    {
        switch ($id_token_signature_alogrithm) {
            case 'HS256':
            case 'ES256':
            case 'RS256':
            case 'PS256':
                return 'sha256';
            case 'HS384':
            case 'ES384':
            case 'RS384':
            case 'PS384':
                return 'sha384';
            case 'HS512':
            case 'ES512':
            case 'RS512':
            case 'PS512':
                return 'sha512';
            default:
                throw $this->getExceptionManager()->getException(
                    ExceptionManagerInterface::INTERNAL_SERVER_ERROR,
                    '',
                    ''
                );
        }
    }

    private function getAtHashSize($id_token_signature_alogrithm)
    {
        switch ($id_token_signature_alogrithm) {
            case 'HS256':
            case 'ES256':
            case 'RS256':
            case 'PS256':
                return 128;
            case 'HS384':
            case 'ES384':
            case 'RS384':
            case 'PS384':
                return 192;
            case 'HS512':
            case 'ES512':
            case 'RS512':
            case 'PS512':
                return 256;
            default:
                throw $this->getExceptionManager()->getException(
                    ExceptionManagerInterface::INTERNAL_SERVER_ERROR,
                    '',
                    ''
                );
        }
    }
}
