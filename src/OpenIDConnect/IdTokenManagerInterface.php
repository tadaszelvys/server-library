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
use OAuth2\EndUser\EndUserInterface;

interface IdTokenManagerInterface
{
    /**
     * @param \OAuth2\Client\ClientInterface   $client
     * @param \OAuth2\EndUser\EndUserInterface $end_user
     * @param array                            $id_token_claims
     * @param string|null                      $access_token
     * @param string|null                      $auth_code
     *
     * @return mixed
     */
    public function createIdToken(ClientInterface $client, EndUserInterface $end_user, array $id_token_claims = [], $access_token = null, $auth_code = null);

    /**
     * @param \OAuth2\OpenIDConnect\IdTokenInterface $token The ID token to revoke
     */
    public function revokeIdToken(IdTokenInterface $token);
}
