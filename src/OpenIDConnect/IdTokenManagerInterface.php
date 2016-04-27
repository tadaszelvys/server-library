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
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\AuthCodeInterface;
use OAuth2\User\UserInterface as BaseUserInterface;

interface IdTokenManagerInterface
{
    /**
     * @param \OAuth2\Client\ClientInterface          $client
     * @param \OAuth2\User\UserInterface              $user
     * @param string                                  $redirect_uri
     * @param string[]                                $scope
     * @param array                                   $id_token_claims
     * @param \OAuth2\Token\AccessTokenInterface|null $access_token
     * @param \OAuth2\Token\AuthCodeInterface|null    $auth_code
     *
     * @return \OAuth2\OpenIDConnect\IdTokenInterface
     */
    public function createIdToken(ClientInterface $client, BaseUserInterface $user, $redirect_uri, array $scope, array $id_token_claims = [], AccessTokenInterface $access_token = null, AuthCodeInterface $auth_code = null);

    /**
     * @param \OAuth2\OpenIDConnect\IdTokenInterface $token The ID token to revoke
     */
    public function revokeIdToken(IdTokenInterface $token);

    /**
     * @return string[]
     */
    public function getSignatureAlgorithms();

    /**
     * @return string[]
     */
    public function getKeyEncryptionAlgorithms();

    /**
     * @return string[]
     */
    public function getContentEncryptionAlgorithms();
}
