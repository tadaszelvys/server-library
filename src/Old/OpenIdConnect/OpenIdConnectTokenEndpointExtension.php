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

use OAuth2\Endpoint\Token\TokenEndpointExtensionInterface;
use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\Client\Client;
use OAuth2\Model\IdToken\IdTokenRepositoryInterface;
use OAuth2\Model\UserAccount\UserAccountRepositoryInterface;

/**
 * Class OpenIdConnectTokenEndpointExtension.
 */
class OpenIdConnectTokenEndpointExtension implements TokenEndpointExtensionInterface
{
    /**
     * @var IdTokenRepositoryInterface
     */
    private $id_token_manager;

    /**
     * @var UserAccountRepositoryInterface
     */
    private $user_account_manager;

    /**
     * OpenIdConnectTokenEndpointExtension constructor.
     *
     * @param IdTokenRepositoryInterface     $id_token_manager
     * @param UserAccountRepositoryInterface $user_account_manager
     */
    public function __construct(IdTokenRepositoryInterface $id_token_manager,
                                UserAccountRepositoryInterface $user_account_manager
    ) {
        $this->id_token_manager = $id_token_manager;
        $this->user_account_manager = $user_account_manager;
    }

    /**
     * {@inheritdoc].
     */
    public function postAccessTokenCreation(Client $client, GrantTypeResponseInterface $grant_type_response, array $token_type_information, AccessTokenInterface $access_token)
    {
        if (false === $this->issueIdToken($grant_type_response)) {
            return;
        }
        $user = $this->user_account_manager->getUserAccountByPublicId($grant_type_response->getUserAccountPublicId());
        if (null === $user) {
            return;
        }

        $claims = [];
        $auth_code = $grant_type_response->getAdditionalData('auth_code');

        if (!$auth_code instanceof AuthCode) {
            return;
        }

        if (array_key_exists('nonce', $params = $auth_code->getQueryParams())) {
            $claims = array_merge(
                $claims,
                ['nonce' => $params['nonce']]
            );
        }

        $requested_claims = $this->getIdTokenClaims($access_token);

        $id_token = $this->id_token_manager->createIdToken(
            $client,
            $user,
            $access_token->getMetadata('redirect_uri'),
            $access_token->getMetadata('claims_locales'),
            $requested_claims,
            $access_token->getScope(),
            $claims,
            $access_token,
            $auth_code
        );

        return $id_token->toArray();
    }

    /**
     * @param AccessToken $access_token
     *
     * @return array
     */
    private function getIdTokenClaims(AccessToken $access_token)
    {
        if (!$access_token->hasMetadata('requested_claims')) {
            return [];
        }

        $requested_claims = $access_token->getMetadata('requested_claims');
        if (true === array_key_exists('id_token', $requested_claims)) {
            return $requested_claims['id_token'];
        }

        return [];
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
    public function preAccessTokenCreation(Client $client, GrantTypeResponseInterface $grant_type_response, array $token_type_information)
    {
        $data = [
            'redirect_uri' => $grant_type_response->getRedirectUri(),
        ];
        if ($grant_type_response->hasAdditionalData('auth_code') && null !== $grant_type_response->getAdditionalData('auth_code')) {
            $data['claims_locales'] = array_key_exists('claims_locales', $grant_type_response->getAdditionalData('auth_code')->getQueryParams()) ? $grant_type_response->getAdditionalData('auth_code')->getQueryParams()['claims_locales'] : null;
            $data['requested_claims'] = array_key_exists('claims', $grant_type_response->getAdditionalData('auth_code')->getQueryParams()) ? $grant_type_response->getAdditionalData('auth_code')->getQueryParams()['claims'] : [];
        } else {
            $data['claims_locales'] = null;
            $data['requested_claims'] = [];
        }

        return $data;
    }
}
