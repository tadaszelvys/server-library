<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ConfidentialClientInterface;
use OAuth2\Endpoint\Authorization;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\PKCEMethod\PKCEMethodInterface;
use OAuth2\Grant\PKCEMethod\Plain;
use OAuth2\Grant\PKCEMethod\S256;
use OAuth2\Token\AuthCodeInterface;
use OAuth2\Token\AuthCodeManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

final class AuthorizationCodeGrantType implements ResponseTypeSupportInterface, GrantTypeSupportInterface
{
    use HasExceptionManager;

    /**
     * @var \OAuth2\Token\AuthCodeManagerInterface
     */
    private $auth_code_manager;

    /**
     * @var \OAuth2\Grant\PKCEMethod\PKCEMethodInterface[]
     */
    private $pkce_methods = [];

    /**
     * AuthorizationCodeGrantType constructor.
     *
     * @param \OAuth2\Token\AuthCodeManagerInterface      $auth_code_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(AuthCodeManagerInterface $auth_code_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->auth_code_manager = $auth_code_manager;
        $this->setExceptionManager($exception_manager);

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
     * @return \OAuth2\Token\AuthCodeManagerInterface
     */
    private function getAuthCodeManager()
    {
        return $this->auth_code_manager;
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
        return 'query';
    }

    /**
     * {@inheritdoc}
     */
    public function grantAuthorization(Authorization $authorization)
    {
        $code = $this->getAuthCodeManager()->createAuthCode($authorization->getClient(), $authorization->getEndUser(), $authorization->getQueryParams(), $authorization->getRedirectUri(), $authorization->getScope(), $authorization->getIssueRefreshToken());
        $params = [
            'code' => $code->getToken(),
        ];
        if (null !== $authorization->getState()) {
            $params['state'] = $authorization->getState();
        }

        return $params;
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

        if (!$authCode instanceof AuthCodeInterface) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_GRANT, "Code doesn't exist or is invalid for the client.");
        }

        $this->checkPKCE($request, $authCode);
        $this->checkAuthCode($authCode, $client);

        $redirect_uri = RequestBody::getParameter($request, 'redirect_uri');

        // Validate the redirect URI.
        $this->checkRedirectUri($authCode, $redirect_uri);

        $this->getAuthCodeManager()->markAuthCodeAsUsed($authCode);

        $grant_type_response->setRequestedScope(RequestBody::getParameter($request, 'scope') ?: $authCode->getScope());
        $grant_type_response->setAvailableScope($authCode->getScope());
        $grant_type_response->setResourceOwnerPublicId($authCode->getResourceOwnerPublicId());
        $grant_type_response->setRefreshTokenIssued($authCode->getIssueRefreshToken());
        $grant_type_response->setRefreshTokenScope($authCode->getScope());
        $grant_type_response->setRefreshTokenRevoked(null);
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
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Missing parameter. "code" is required.');
        }

        return $this->getAuthCodeManager()->getAuthCode($code);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\Client\ClientInterface           $client
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkClient(ServerRequestInterface $request, ClientInterface $client)
    {
        if (!$client instanceof ConfidentialClientInterface) {
            if (null === ($client_id = RequestBody::getParameter($request, 'client_id')) || $client_id !== $client->getPublicId()) {
                throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The client_id parameter is required for non-confidential clients.');
            }
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\Token\AuthCodeInterface          $authCode
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface
     */
    private function checkPKCE(ServerRequestInterface $request, AuthCodeInterface $authCode)
    {
        $params = $authCode->getQueryParams();
        if (!array_key_exists('code_challenge', $params)) {
            return;
        }

        $code_challenge = $params['code_challenge'];
        $code_challenge_method = array_key_exists('code_challenge_method', $params) ? $params['code_challenge_method'] : 'plain';

        if (!array_key_exists($code_challenge_method, $this->getPKCEMethods())) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, sprintf('Unsupported code challenge method "%s".', $code_challenge_method));
        }
        $method = $this->getPKCEMethod($code_challenge_method);

        $code_verifier = RequestBody::getParameter($request, 'code_verifier');
        if (null === $code_verifier) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "code_verifier" is required.');
        }
        if (!$method->isChallengeVerified($code_verifier, $code_challenge)) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'Invalid parameter "code_verifier".');
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
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_REQUEST, 'The redirect URI is missing or does not match.');
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
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_GRANT, "Code doesn't exist or is invalid for the client.");
        }

        if ($authCode->hasExpired()) {
            throw $this->getExceptionManager()->getException(ExceptionManagerInterface::BAD_REQUEST, ExceptionManagerInterface::INVALID_GRANT, 'The authorization code has expired.');
        }
    }
}
