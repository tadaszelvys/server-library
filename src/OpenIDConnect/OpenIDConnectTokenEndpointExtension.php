<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;

use OAuth2\Client\ClientInterface;
use OAuth2\Endpoint\TokenEndpointExtensionInterface;
use OAuth2\EndUser\EndUserManagerInterface;
use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\AuthCodeInterface;

/**
 * Class OpenIDConnectTokenEndpointExtension.
 */
final class OpenIDConnectTokenEndpointExtension implements TokenEndpointExtensionInterface
{
    /**
     * @var \OAuth2\OpenIDConnect\IdTokenManagerInterface
     */
    private $id_token_manager;

    /**
     * @var \OAuth2\EndUser\EndUserManagerInterface
     */
    private $end_user_manager;

    /**
     * OpenIDConnectTokenEndpointExtension constructor.
     *
     * @param \OAuth2\OpenIDConnect\IdTokenManagerInterface $id_token_manager
     * @param \OAuth2\EndUser\EndUserManagerInterface       $end_user_manager
     */
    public function __construct(IdTokenManagerInterface $id_token_manager,
                                EndUserManagerInterface $end_user_manager
    ) {
        $this->id_token_manager = $id_token_manager;
        $this->end_user_manager = $end_user_manager;
    }

    /**
     * {@inheritdoc].
     */
    public function process(ClientInterface $client, GrantTypeResponseInterface $grant_type_response, array $token_type_information, AccessTokenInterface $access_token)
    {
        if (false === $this->issueIdToken($grant_type_response)) {
            return;
        }
        $end_user = $this->end_user_manager->getEndUser($grant_type_response->getResourceOwnerPublicId());
        if (null === $end_user) {
            return;
        }

        $claims = [];
        $auth_code = $grant_type_response->getAdditionalData('auth_code');

        if ($auth_code instanceof AuthCodeInterface && array_key_exists('nonce', $params = $auth_code->getQueryParams())) {
            $claims = array_merge(
                $claims,
                ['nonce' => $params['nonce']]
            );
        }

        $id_token = $this->id_token_manager->createIdToken(
            $client,
            $end_user,
            $claims,
            $access_token->getToken(),
            $auth_code instanceof AuthCodeInterface ? $auth_code->getToken() : null
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
}
