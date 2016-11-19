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

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Behaviour\HasTokenTypeParameterSupport;
use OAuth2\Endpoint\Authorization\AuthorizationInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;

final class ImplicitGrantType implements ResponseTypeInterface
{
    use HasExceptionManager;
    use HasTokenTypeManager;
    use HasAccessTokenManager;
    use HasTokenTypeParameterSupport;

    /**
     * @var bool
     */
    private $confidential_clients_allowed = false;

    /**
     * ImplicitGrantType constructor.
     *
     * @param \OAuth2\Token\TokenTypeManagerInterface     $token_type_manager
     * @param \OAuth2\Token\AccessTokenManagerInterface   $access_token_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(TokenTypeManagerInterface $token_type_manager, AccessTokenManagerInterface $access_token_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->setTokenTypeManager($token_type_manager);
        $this->setAccessTokenManager($access_token_manager);
        $this->setExceptionManager($exception_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedGrantTypes()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return 'token';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode()
    {
        return self::RESPONSE_TYPE_MODE_FRAGMENT;
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeAuthorization(array &$response_parameters, AuthorizationInterface $authorization, $redirect_uri)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function prepareAuthorization(AuthorizationInterface $authorization)
    {
        if (false === $this->areConfidentialClientsAllowed() && false === $authorization->getClient()->isPublic()) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_CLIENT, 'Confidential clients are not allowed to use the implicit grant type.');
        }
        $token_type = $this->getTokenTypeFromRequest($authorization->getQueryParams());

        $token = $this->getAccessTokenManager()->createAccessToken(
            $authorization->getClient(),
            $authorization->getUserAccount(),
            $token_type->getTokenTypeInformation(),
            $authorization->getQueryParams(),
            $authorization->getScopes(),
            null, // Refresh token
            null, // Resource Server
            ['redirect_uri' => $authorization->getRedirectUri()]
        );

        $authorization->setData('access_token', $token);

        return $token->toArray();
    }

    /**
     * @return bool
     */
    public function areConfidentialClientsAllowed()
    {
        return $this->confidential_clients_allowed;
    }

    public function allowConfidentialClients()
    {
        $this->confidential_clients_allowed = true;
    }

    public function disallowConfidentialClients()
    {
        $this->confidential_clients_allowed = false;
    }
}
