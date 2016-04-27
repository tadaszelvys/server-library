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
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use OAuth2\ResourceServer\ResourceServerInterface;

interface AccessTokenManagerInterface
{
    /**
     * Creates an access token and stores it if necessary.
     *
     * @param \OAuth2\Client\ClientInterface                      $client                The client associated with this access token.
     * @param \OAuth2\ResourceOwner\ResourceOwnerInterface        $resource_owner        Resource owner associated with the access token.
     * @param array                                               $token_type_parameters The parameters from token type to add to the access token
     * @param array                                               $request_parameters    The parameters of the request
     * @param string[]                                            $scope                 (optional) Scopes of the access token.
     * @param \OAuth2\Token\RefreshTokenInterface|null            $refresh_token         (optional) Refresh token associated with the access token.
     * @param \OAuth2\ResourceServer\ResourceServerInterface|null $resource_server       (optional) The resource server.
     * @param string|null                                         $redirect_uri          (optional) The redirect Uri.
     *
     * @return \OAuth2\Token\AccessTokenInterface
     */
    public function createAccessToken(ClientInterface $client, ResourceOwnerInterface $resource_owner, array $token_type_parameters, array $request_parameters, array $scope = [], RefreshTokenInterface $refresh_token = null, ResourceServerInterface $resource_server = null, $redirect_uri = null);
    
    /**
     * This function revoke an access token.
     *
     * @param \OAuth2\Token\AccessTokenInterface $token The access token to revoke
     */
    public function revokeAccessToken(AccessTokenInterface $token);

    /**
     * This function verifies the request and validate or not the access token.
     * MUST return null if the access token is not valid (expired, revoked...).
     *
     * @param string $access_token The access token
     *
     * @return \OAuth2\Token\AccessTokenInterface|null Return the access token or null if the argument is not a valid access token
     */
    public function getAccessToken($access_token);

    /**
     * @param \OAuth2\Token\AccessTokenInterface $token
     *
     * @return bool True if the access token is valid, else false
     */
    public function isAccessTokenValid(AccessTokenInterface $token);

    /**
     * @param \OAuth2\Token\TokenUpdaterInterface $token_updater
     */
    public function addTokenUpdater(TokenUpdaterInterface $token_updater);
}
