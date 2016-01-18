<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

use OAuth2\Client\ClientInterface;
use OAuth2\EndUser\EndUserInterface;

interface IdTokenManagerInterface
{
    /**
     * @param \OAuth2\Client\ClientInterface   $client
     * @param \OAuth2\EndUser\EndUserInterface $end_user
     * @param array                            $token_type_information
     * @param null|string                      $at_hash
     * @param null|string                      $c_hash
     *
     * @return mixed
     */
    public function createIdToken(ClientInterface $client, EndUserInterface $end_user, array $token_type_information, $at_hash = null, $c_hash = null);

    /**
     * @param \OAuth2\Token\IdTokenInterface $token The ID token to revoke
     */
    public function revokeIdToken(IdTokenInterface $token);

    /**
     * @param string $id_token The ID token
     *
     * @return \OAuth2\Token\IdTokenInterface|null Return the ID token or null
     */
    public function getIdToken($id_token);
}
