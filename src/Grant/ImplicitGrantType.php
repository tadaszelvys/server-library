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
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use OAuth2\TokenType\TokenTypeManagerInterface;

class ImplicitGrantType implements ResponseTypeInterface
{
    /**
     * @var bool
     */
    private $confidentialClientsAllowed = false;

    /**
     * @var TokenTypeManagerInterface
     */
    private $token_type_manager;

    /**
     * @var AccessTokenRepositoryInterface
     */
    private $access_token_manager;

    /**
     * ImplicitGrantType constructor.
     *
     * @param TokenTypeManagerInterface     $token_type_manager
     * @param AccessTokenRepositoryInterface   $access_token_manager
     */
    public function __construct(TokenTypeManagerInterface $token_type_manager, AccessTokenRepositoryInterface $access_token_manager)
    {
        $this->token_type_manager = $token_type_manager;
        $this->access_token_manager = $access_token_manager;
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedGrantTypes(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType(): string
    {
        return 'token';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode(): string
    {
        return self::RESPONSE_TYPE_MODE_FRAGMENT;
    }

    /**
     * {@inheritdoc}
     */
    public function checkAuthorization(Authorization $authorization)
    {
        if (false === $this->areConfidentialClientsAllowed() && false === $authorization->getClient()->isPublic()) {
            throw new OAuth2Exception(
                400,
                [
                    'error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_CLIENT,
                    'error_description' => 'Confidential clients are not allowed to use the implicit grant type.'
                ]
            );
        }
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
        $token_type = $this->getTokenTypeFromRequest($authorization->getQueryParams());

        $token = $this->access_token_manager->create(
            $authorization->getClient(),
            $authorization->getUserAccount(),
            $token_type->getTokenTypeInformation(),
            $authorization->getQueryParams(),
            $authorization->getScopes(),
            null, // Refresh token
            null, // Resource Server
            ['redirect_uri' => $authorization->getRedirectUri()]
        );

        $authorization = $authorization->withData('access_token', $token);

        return $token->toArray();
    }

    /**
     * @return bool
     */
    public function areConfidentialClientsAllowed(): bool
    {
        return $this->confidentialClientsAllowed;
    }

    public function allowConfidentialClients()
    {
        $this->confidentialClientsAllowed = true;
    }

    public function disallowConfidentialClients()
    {
        $this->confidentialClientsAllowed = false;
    }
}
