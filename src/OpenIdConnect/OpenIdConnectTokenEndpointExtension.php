<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect;

use OAuth2\Client\ClientInterface;
use OAuth2\Endpoint\TokenEndpointExtensionInterface;
use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\AuthCodeInterface;
use OAuth2\User\UserManagerInterface;

/**
 * Class OpenIdConnectTokenEndpointExtension.
 */
final class OpenIdConnectTokenEndpointExtension implements TokenEndpointExtensionInterface
{
    /**
     * @var \OAuth2\OpenIdConnect\IdTokenManagerInterface
     */
    private $id_token_manager;

    /**
     * @var \OAuth2\User\UserManagerInterface
     */
    private $user_manager;

    /**
     * OpenIdConnectTokenEndpointExtension constructor.
     *
     * @param \OAuth2\OpenIdConnect\IdTokenManagerInterface $id_token_manager
     * @param \OAuth2\User\UserManagerInterface             $user_manager
     */
    public function __construct(IdTokenManagerInterface $id_token_manager,
                                UserManagerInterface $user_manager
    ) {
        $this->id_token_manager = $id_token_manager;
        $this->user_manager = $user_manager;
    }

    /**
     * {@inheritdoc].
     */
    public function postAccessTokenCreation(ClientInterface $client, GrantTypeResponseInterface $grant_type_response, array $token_type_information, AccessTokenInterface $access_token)
    {
        if (false === $this->issueIdToken($grant_type_response)) {
            return;
        }
        $user = $this->user_manager->getUser($grant_type_response->getResourceOwnerPublicId());
        if (null === $user) {
            return;
        }

        $claims = [];
        $auth_code = $grant_type_response->getAdditionalData('auth_code');

        if (!$auth_code instanceof AuthCodeInterface) {
            return;
        }

        if (array_key_exists('nonce', $params = $auth_code->getQueryParams())) {
            $claims = array_merge(
                $claims,
                ['nonce' => $params['nonce']]
            );
        }
        
        $id_token = $this->id_token_manager->createIdToken(
            $client,
            $user,
            $access_token->getMetadata('redirect_uri'),
            $access_token->getMetadata('requested_claims'),
            $access_token->getScope(),
            $claims,
            $access_token,
            $auth_code
        );

        return $id_token->toArray();
    }

    /**
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     *
     * @return bool
     */
    private function issueIdToken(GrantTypeResponseInterface $grant_type_response)
    {
        $scope = $grant_type_response->getRequestedScope();

        return is_array($scope) && in_array('openid', $scope);
    }

    /**
     * {@inheritdoc}
     */
    public function preAccessTokenCreation(ClientInterface $client, GrantTypeResponseInterface $grant_type_response, array $token_type_information)
    {
        $data = [
            'redirect_uri' => $grant_type_response->getRedirectUri(),
        ];
        if ($grant_type_response->hasAdditionalData('auth_code') && null !== $grant_type_response->getAdditionalData('auth_code')) {
            $data['requested_claims'] = array_key_exists('claims', $grant_type_response->getAdditionalData('auth_code')->getQueryParams()) ? $grant_type_response->getAdditionalData('auth_code')->getQueryParams()['claims'] : [];
        } else {
            $data['requested_claims'] = [];
        }
        
        return $data;
    }
}
