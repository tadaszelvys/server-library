<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint;

use OAuth2\Client\ClientInterface;
use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Token\AccessTokenInterface;

interface TokenEndpointExtensionInterface
{
    /**
     * @param \OAuth2\Client\ClientInterface           $client
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     * @param array                                    $token_type_information
     *
     * @return array|null
     */
    public function preAccessTokenCreation(ClientInterface $client, GrantTypeResponseInterface $grant_type_response, array $token_type_information);
    
    /**
     * @param \OAuth2\Client\ClientInterface           $client
     * @param \OAuth2\Grant\GrantTypeResponseInterface $grant_type_response
     * @param array                                    $token_type_information
     * @param \OAuth2\Token\AccessTokenInterface       $access_token
     *
     * @return array|null
     */
    public function postAccessTokenCreation(ClientInterface $client, GrantTypeResponseInterface $grant_type_response, array $token_type_information, AccessTokenInterface $access_token);
}
