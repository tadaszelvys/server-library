<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Token;

use OAuth2\Grant\GrantTypeResponseInterface;
use OAuth2\Model\Client\Client;
use OAuth2\Token\AccessTokenInterface;

interface TokenEndpointExtensionInterface
{
    /**
     * @param Client                     $client
     * @param GrantTypeResponseInterface $grant_type_response
     * @param array                      $token_type_information
     *
     * @return array|null
     */
    public function preAccessTokenCreation(Client $client, GrantTypeResponseInterface $grant_type_response, array $token_type_information);

    /**
     * @param Client                     $client
     * @param GrantTypeResponseInterface $grant_type_response
     * @param array                      $token_type_information
     * @param AccessToken                $access_token
     *
     * @return array|null
     */
    public function postAccessTokenCreation(Client $client, GrantTypeResponseInterface $grant_type_response, array $token_type_information, AccessTokenInterface $access_token);
}
