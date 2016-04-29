<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasAuthorizationCodeManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasScopeManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Endpoint\Authorization;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\PKCEMethod\PKCEMethodInterface;
use OAuth2\Grant\PKCEMethod\Plain;
use OAuth2\Grant\PKCEMethod\S256;
use OAuth2\Scope\ScopeManagerInterface;
use OAuth2\Token\AuthCodeInterface;
use OAuth2\Token\AuthCodeManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationCodeGrantType implements ResponseTypeSupportInterface, GrantTypeSupportInterface
{
    use HasExceptionManager;
    use HasAuthorizationCodeManager;
    use HasScopeManager;

    /**
     * @var \OAuth2\Grant\PKCEMethod\PKCEMethodInterface[]
     */
    private $pkce_methods = [];

    /**
     * @var bool
     */
    private $pkce_for_public_clients_enforced = false;

    /**
     * AuthorizationCodeGrantType constructor.
     *
     * @param \OAuth2\Token\AuthCodeManagerInterface      $auth_code_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     * @param \OAuth2\Scope\ScopeManagerInterface         $scope_manager
     */
    public function __construct(AuthCodeManagerInterface $auth_code_manager,
                                ExceptionManagerInterface $exception_manager,
                                ScopeManagerInterface $scope_manager
    ) {
        $this->setAuthorizationCodeManager($auth_code_manager);
        $this->setExceptionManager($exception_manager);
        $this->setScopeManager($scope_manager);

        $this->addPKCEMethod(new Plain());
        $this->addPKCEMethod(new S256());
    }

    /**
     * @param \OAuth2\Grant\PKCEMethod\PKCEMethodInterface $method
     */
    public function addPKCEMethod(PKCEMethodInterface $method)
    {
        if (!array_key_exists($method->getMethodName(), $this->pkce_methods)) {
            $this->pkce_methods[$method->getMethodName()] = $method;
        }
    }

    /**
     * @return \OAuth2\Grant\PKCEMethod\PKCEMethodInterface[]
     */
    private function getPKCEMethods()
    {
        return $this->pkce_methods;
    }

    /**
     * @param string $method
     *
     * @return \OAuth2\Grant\PKCEMethod\PKCEMethodInterface
     */
    private function getPKCEMethod($method)
    {
        return $this->pkce_methods[$method];
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return 'code';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode()
    {
        return self::RESPONSE_TYPE_MODE_QUERY;
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeAuthorization(array &$response_parameters, Authorization $authorization, $redirect_uri)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function prepareAuthorization(Authorization $authorization)
    {
        $code = $this->getAuthorizationCodeManager()->createAuthCode(
            $authorization->getClient(),
            $authorization->getUser(),
            $authorization->getQueryParams(),
            $authorization->has('redirect_uri') ? $authorization->get('redirect_uri') : null,
            $authorization->getScopes(),
            $authorization->has('issue_refresh_token') ? $authorization->get('issue_refresh_token') : false
        );

        $authorization->setData('code', $code);

        return $code->toArray();
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType()
    {
        return 'authorization_code';
    }

    /**
     * {@inheritdoc}
     */
    public function isSupported(array $request_parameters)
    {
        if (array_key_exists('grant_type', $request_parameters)) {
            return $this->getGrantType() === $request_parameters['grant_type'];
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function prepareGrantTypeResponse(ServerRequestInterface $request, GrantTypeResponseInterface &$grant_type_response)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function grantAccessToken(ServerRequestInterface $request, ClientInterface $client, GrantTypeResponseInterface &$grant_type_response)
    {
        $this->checkClient($request, $client);
        $authCode = $this->getAuthCode($request);

        $this->checkPKCE($request, $authCode, $client);
        $this->checkAuthCode($authCode, $client);

        $redirect_uri = RequestBody::getParameter($request, 'redirect_uri');

        // Validate the redirect URI.
        $this->checkRedirectUri($authCode, $redirect_uri);

        $this->getAuthorizationCodeManager()->markAuthCodeAsUsed($authCode);

        $grant_type_response->setRequestedScope(RequestBody::getParameter($request, 'scope') ? $this->getScopeManager()->convertToArray(RequestBody::getParameter($request, 'scope')) : $authCode->getScope());
        $grant_type_response->setAvailableScope($authCode->getScope());
        $grant_type_response->setResourceOwnerPublicId($authCode->getResourceOwnerPublicId());
        $grant_type_response->setRedirectUri($authCode->getRedirectUri());

        // Refresh Token
        $grant_type_response->setRefreshTokenIssued($authCode->getIssueRefreshToken());
        $grant_type_response->setRefreshTokenScope($authCode->getScope());
        $grant_type_response->setAdditionalData('auth_code', $authCode);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     *
     * @return null|\OAuth2\Token\AuthCodeInterface
     */
    private function getAuthCode(ServerRequestInterface $request)
    {
        $code = RequestBody::getParameter($request, 'code');
        if (null === $code) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Missing parameter. "code" is required.');
        }

        $auth_code = $this->getAuthorizationCodeManager()->getAuthCode($code);

        if (!$auth_code instanceof AuthCodeInterface) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_GRANT, "Code doesn't exist or is invalid for the client.");
        }

        return $auth_code;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\Client\ClientInterface           $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkClient(ServerRequestInterface $request, ClientInterface $client)
    {
        if (true === $client->isPublic()) {
            if (null === ($client_id = RequestBody::getParameter($request, 'client_id')) || $client_id !== $client->getPublicId()) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The client_id parameter is required for non-confidential clients.');
            }
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\Token\AuthCodeInterface          $authCode
     * @param \OAuth2\Client\ClientInterface           $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkPKCE(ServerRequestInterface $request, AuthCodeInterface $authCode, ClientInterface $client)
    {
        $params = $authCode->getQueryParams();
        if (!array_key_exists('code_challenge', $params)) {
            if (true === $this->isPKCEForPublicClientsEnforced() && $client->isPublic()) {
                throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Non-confidential clients must set a proof key (PKCE) for code exchange.');
            }

            return;
        }

        $code_challenge = $params['code_challenge'];
        $code_challenge_method = array_key_exists('code_challenge_method', $params) ? $params['code_challenge_method'] : 'plain';
        $code_verifier = RequestBody::getParameter($request, 'code_verifier');

        $this->checkPKCEInput($code_challenge_method, $code_challenge, $code_verifier);
    }

    /**
     * @param string $code_challenge_method
     * @param string $code_challenge
     * @param string $code_verifier
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkPKCEInput($code_challenge_method, $code_challenge, $code_verifier)
    {
        if (!array_key_exists($code_challenge_method, $this->getPKCEMethods())) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, sprintf('Unsupported code challenge method "%s".', $code_challenge_method));
        }
        $method = $this->getPKCEMethod($code_challenge_method);

        if (null === $code_verifier) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "code_verifier" is required.');
        }
        if (!$method->isChallengeVerified($code_verifier, $code_challenge)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Invalid parameter "code_verifier".');
        }
    }

    /**
     * @param \OAuth2\Token\AuthCodeInterface $authCode
     * @param string                          $redirect_uri
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkRedirectUri(AuthCodeInterface $authCode, $redirect_uri)
    {
        if (null !== $authCode->getRedirectUri() && $redirect_uri !== $authCode->getRedirectUri()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The redirect URI is missing or does not match.');
        }
    }

    /**
     * @param \OAuth2\Token\AuthCodeInterface $authCode
     * @param \OAuth2\Client\ClientInterface  $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkAuthCode(AuthCodeInterface $authCode, ClientInterface $client)
    {
        if ($client->getPublicId() !== $authCode->getClientPublicId()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_GRANT, "Code doesn't exist or is invalid for the client.");
        }

        if ($authCode->hasExpired()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_GRANT, 'The authorization code has expired.');
        }
    }

    /**
     * @return bool
     */
    public function isPKCEForPublicClientsEnforced()
    {
        return $this->pkce_for_public_clients_enforced;
    }

    public function enablePKCEForPublicClientsEnforcement()
    {
        $this->pkce_for_public_clients_enforced = true;
    }

    public function disablePKCEForPublicClientsEnforcement()
    {
        $this->pkce_for_public_clients_enforced = false;
    }
}
