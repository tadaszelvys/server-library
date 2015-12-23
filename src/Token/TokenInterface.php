<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Token;

interface TokenInterface
{
    /**
     * @return string
     */
    public function getToken();

    /**
     * @param string $token
     */
    public function setToken($token);

    /**
     * @return string The public ID of the client associated with the token
     */
    public function getClientPublicId();

    /**
     * @param string $client_public_id
     */
    public function setClientPublicId($client_public_id);

    /**
     * @return int
     */
    public function getExpiresAt();

    /**
     * @param int $expires_at
     */
    public function setExpiresAt($expires_at);

    /**
     * @return bool true if the token has expired
     */
    public function hasExpired();

    /**
     * @return int Seconds before the token expiration date
     */
    public function getExpiresIn();

    /**
     * The scopes associated with the token.
     *
     * @return string[] An array of scope
     */
    public function getScope();

    /**
     * @param array $scope
     */
    public function setScope(array $scope);

    /**
     * The resource owner associated to the token.
     *
     * @return string The public ID of the resource owner associated with the token
     */
    public function getResourceOwnerPublicId();

    /**
     * @param string $resource_owner_public_id
     */
    public function setResourceOwnerPublicId($resource_owner_public_id);
}
