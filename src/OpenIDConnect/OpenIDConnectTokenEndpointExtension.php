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
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Token\AccessTokenInterface;

/**
 * Class OpenIDConnectTokenEndpointExtension
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
     * @var \OAuth2\Exception\ExceptionManagerInterface
     */
    private $exception_manager;

    /**
     * OpenIDConnectTokenEndpointExtension constructor.
     *
     * @param \OAuth2\OpenIDConnect\IdTokenManagerInterface $id_token_manager
     * @param \OAuth2\EndUser\EndUserManagerInterface       $end_user_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface   $exception_manager
     */
    public function __construct(IdTokenManagerInterface $id_token_manager,
                                EndUserManagerInterface $end_user_manager,
                                ExceptionManagerInterface $exception_manager
    ) {
        $this->id_token_manager = $id_token_manager;
        $this->end_user_manager = $end_user_manager;
        $this->exception_manager = $exception_manager;
    }

    /**
     * {@inheritdoc]
     */
    public function process(ClientInterface $client, GrantTypeResponseInterface $grant_type_response, array $token_type_information, AccessTokenInterface $access_token)
    {
        if (true === $grant_type_response->isIdTokenIssued()) {
            $id_token = $this->id_token_manager->createIdToken(
                $client,
                $this->end_user_manager->getEndUser($grant_type_response->getResourceOwnerPublicId()),
                $token_type_information,
                $grant_type_response->getIdTokenClaims(),
                $access_token,
                $grant_type_response->getAuthorizationCodeToHash()
            );

            return $id_token->toArray();
        }
    }
}
