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

use OAuth2\Endpoint\Authorization\Authorization;
use OAuth2\Grant\PKCEMethod\PKCEMethodManagerInterface;
use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\AuthCode\AuthCodeRepositoryInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Scope\ScopeRepositoryInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

class AuthorizationCodeGrantType implements ResponseTypeInterface, GrantTypeInterface
{
    /**
     * @var bool
     */
    private $pkceForPublicClientsEnforced = false;

    /**
     * @var bool
     */
    private $publicClientsAllowed = false;

    /**
     * @var AuthCodeRepositoryInterface
     */
    private $authCodeRepository;

    /**
     * @var PKCEMethodManagerInterface
     */
    private $pkceMethodManager;

    /**
     * @var ScopeRepositoryInterface
     */
    private $scopeRepository;

    /**
     * AuthorizationCodeGrantType constructor.
     *
     * @param AuthCodeRepositoryInterface $authCodeRepository
     * @param PKCEMethodManagerInterface  $pkceMethodManager
     */
    public function __construct(AuthCodeRepositoryInterface $authCodeRepository, PKCEMethodManagerInterface $pkceMethodManager)
    {
        $this->authCodeRepository = $authCodeRepository;
        $this->pkceMethodManager = $pkceMethodManager;
    }

    /**
     * @param ScopeRepositoryInterface $scopeRepository
     */
    public function enableScopeSupport(ScopeRepositoryInterface $scopeRepository)
    {
        $this->scopeRepository = $scopeRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedResponseTypes(): array
    {
        return ['code'];
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedGrantTypes(): array
    {
        return ['authorization_code'];
    }

    /**
     * @return bool
     */
    public function arePublicClientsAllowed(): bool
    {
        return $this->publicClientsAllowed;
    }

    public function allowPublicClients()
    {
        $this->publicClientsAllowed = true;
    }

    public function disallowPublicClients()
    {
        $this->publicClientsAllowed = false;
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType(): string
    {
        return 'code';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode(): string
    {
        return self::RESPONSE_TYPE_MODE_QUERY;
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeAuthorization(array &$response_parameters, Authorization $authorization, UriInterface $redirect_uri)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function prepareAuthorization(Authorization $authorization)
    {
        $offline_access = $this->isOfflineAccess($authorization);

        $code = $this->authCodeRepository->createAuthCode(
            $authorization->getClient(),
            $authorization->getUserAccount(),
            $authorization->getQueryParams(),
            $authorization->getQueryParam('redirect_uri') ? $authorization->getQueryParam('redirect_uri') : null,
            $authorization->getScopes(),
            $offline_access
        );

        $authorization = $authorization->withData('code', $code);

        return $code->toArray();
    }

    /**
     * {@inheritdoc}
     */
    public function getGrantType(): string
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
    public function grantAccessToken(ServerRequestInterface $request, Client $client, GrantTypeResponseInterface &$grant_type_response)
    {
        $this->checkClient($request, $client);
        $authCode = $this->getAuthCode($request);

        $this->checkPKCE($request, $authCode, $client);
        $this->checkAuthCode($authCode, $client);

        $redirect_uri = RequestBody::getParameter($request, 'redirect_uri');

        // Validate the redirect URI.
        $this->checkRedirectUri($authCode, $redirect_uri);

        $this->authCodeRepository->markAuthCodeAsUsed($authCode);

        if ($this->hasScopeManager()) {
            $grant_type_response->setRequestedScope(RequestBody::getParameter($request, 'scope') ? $this->getScopeManager()->convertToArray(RequestBody::getParameter($request, 'scope')) : $authCode->getScope());
            $grant_type_response->setAvailableScope($authCode->getScope());
            $grant_type_response->setRefreshTokenScope($authCode->getScope());
        }
        $grant_type_response->setResourceOwnerPublicId($authCode->getResourceOwnerPublicId());
        $grant_type_response->setUserAccountPublicId($authCode->getUserAccountPublicId());
        $grant_type_response->setRedirectUri($authCode->getMetadata('redirect_uri'));

        // Refresh Token
        $grant_type_response->setRefreshTokenIssued($authCode->getIssueRefreshToken());
        $grant_type_response->setAdditionalData('auth_code', $authCode);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @throws \OAuth2\Response\OAuth2Exception
     *
     * @return null|\OAuth2\Model\AuthCode\AuthCode
     */
    private function getAuthCode(ServerRequestInterface $request)
    {
        $code = RequestBody::getParameter($request, 'code');
        if (null === $code) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'error_description' => 'Missing parameter. \'code\' is required.',
                ]
            );
        }

        $auth_code = $this->authCodeRepository->getAuthCode($code);

        if (!$auth_code instanceof AuthCode) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_GRANT,
                    'error_description' => 'Code doesn\'t exist or is invalid for the client.',
                ]
            );
        }

        return $auth_code;
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param Client                                   $client
     *
     * @throws \OAuth2\Response\OAuth2Exception
     */
    private function checkClient(ServerRequestInterface $request, Client $client)
    {
        if (true === $client->isPublic()) {
            if (null === ($client_id = RequestBody::getParameter($request, 'client_id')) || $client_id !== $client->getPublicId()) {
                throw new OAuth2Exception(
                    400,
                    [
                        'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                        'error_description' => 'The client_id parameter is required for non-confidential clients.',
                    ]
                );
            }
        }
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \OAuth2\Model\AuthCode\AuthCode          $authCode
     * @param Client                                   $client
     *
     * @throws \OAuth2\Response\OAuth2Exception
     */
    private function checkPKCE(ServerRequestInterface $request, AuthCode $authCode, Client $client)
    {
        $params = $authCode->getQueryParams();
        if (!array_key_exists('code_challenge', $params)) {
            if (true === $this->isPKCEForPublicClientsEnforced() && $client->isPublic()) {
                throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'Non-confidential clients must set a proof key (PKCE) for code exchange.']));
            }

            return;
        }

        $code_challenge = $params['code_challenge'];
        $code_challenge_method = array_key_exists('code_challenge_method', $params) ? $params['code_challenge_method'] : 'plain';
        $code_verifier = RequestBody::getParameter($request, 'code_verifier');

        try {
            $this->getPKCEMethodManager()->checkPKCEInput($code_challenge_method, $code_challenge, $code_verifier);
        } catch (\InvalidArgumentException $e) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => $e->getMessage()]));
        }
    }

    /**
     * @param \OAuth2\Model\AuthCode\AuthCode $authCode
     * @param string                          $redirect_uri
     *
     * @throws \OAuth2\Response\OAuth2Exception
     */
    private function checkRedirectUri(AuthCode $authCode, $redirect_uri)
    {
        if (true === $authCode->hasMetadata('redirect_uri') && $redirect_uri !== $authCode->getMetadata('redirect_uri')) {
            throw new OAuth2Exception(
                400,
                [
                    'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST,
                    'The redirect URI is missing or does not match.',
                ]
            );
        }
    }

    /**
     * @param \OAuth2\Model\AuthCode\AuthCode $authCode
     * @param Client                          $client
     *
     * @throws \OAuth2\Response\OAuth2Exception
     */
    private function checkAuthCode(AuthCode $authCode, Client $client)
    {
        if ($client->getId() !== $authCode->getClientPublicId()) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_GRANT,
                    'error_description' => "Code doesn't exist or is invalid for the client.",
                ]
            );
        }

        if ($authCode->hasExpired()) {
            throw new OAuth2Exception(
                400,
                [
                    'error'             => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_GRANT,
                    'error_description' => 'The authorization code has expired.',
                ]
            );
        }
    }

    /**
     * @return bool
     */
    public function isPKCEForPublicClientsEnforced(): bool
    {
        return $this->pkceForPublicClientsEnforced;
    }

    /**
     * When this method is called, the PKCE is enforced.
     */
    public function enablePKCEForPublicClientsEnforcement()
    {
        $this->pkceForPublicClientsEnforced = true;
    }

    /**
     * When this method is called, the PKCE is not enforced.
     */
    public function disablePKCEForPublicClientsEnforcement()
    {
        $this->pkceForPublicClientsEnforced = false;
    }

    /**
     * @param \OAuth2\Endpoint\Authorization\Authorization $authorization
     *
     * @return bool
     */
    private function isOfflineAccess(Authorization $authorization)
    {
        // The scope offline_access is not requested
        if (!in_array('offline_access', $authorization->getScopes())) {
            return false;
        }

        // The scope offline_access is requested but prompt is not consent
        // The scope offline_access is ignored
        if (!$authorization->hasQueryParam('prompt') || !in_array('consent', $authorization->getQueryParam('prompt'))) {
            $authorization = $authorization->withoutScope('offline_access');

            return false;
        }

        return true;
    }
}
