<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResponseType;

use OAuth2\Endpoint\Authorization\Authorization;
use OAuth2\Endpoint\Token\GrantTypeData;
use OAuth2\Model\AuthCode\AuthCodeRepositoryInterface;
use OAuth2\Model\Scope\ScopeRepository;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

final class CodeResponseType implements ResponseTypeInterface
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
     * @var ScopeRepository
     */
    private $scopeRepository;

    /**
     * AuthorizationCodeGrantType constructor.
     *
     * @param AuthCodeRepositoryInterface $authCodeRepository
     */
    public function __construct(AuthCodeRepositoryInterface $authCodeRepository)
    {
        $this->authCodeRepository = $authCodeRepository;
    }

    /**
     * @param ScopeRepository $scopeRepository
     */
    public function enableScopeSupport(ScopeRepository $scopeRepository)
    {
        $this->scopeRepository = $scopeRepository;
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

        if (!array_key_exists('code_challenge', $params)) {
            if (true === $this->isPKCEForPublicClientsEnforced() && $client->isPublic()) {
                throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'Non-confidential clients must set a proof key (PKCE) for code exchange.']);
            }

            return;
        }

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
    public function checkTokenRequest(ServerRequestInterface $request)
    {
        $parameters = $request->getParsedBody() ?? [];
        $requiredParameters = ['code'];

        foreach ($requiredParameters as $requiredParameter) {
            if (!array_key_exists($requiredParameter, $parameters)) {
                throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => sprintf('The parameter \'%s\' is missing.', $requiredParameter)]);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function prepareTokenResponse(ServerRequestInterface $request, GrantTypeData $grantTypeResponse): GrantTypeData
    {
        //Nothing to do
        return $grantTypeResponse;
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
