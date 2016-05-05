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
     * @param string $scope
     *
     * @return bool
     */
    public function hasScope($scope);

    /**
     * The scopes associated with the token.
     *
     * @return string[] An array of scope
     */
    public function getScope();

    /**
     * @param string[] $scope
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

    /**
     * Other parameters.
     *
     * @return array
     */
    public function getParameters();

    /**
     * @param string $key
     *
     * @throws \InvalidArgumentException
     *
     * @return mixed
     */
    public function getParameter($key);

    /**
     * @param string $key
     *
     * @return bool
     */
    public function hasParameter($key);

    /**
     * @param array $parameters
     */
    public function setParameters(array $parameters);

    /**
     * @param string $key
     * @param mixed  $value
     */
    public function setParameter($key, $value);

    /**
     * @param string $key
     */
    public function unsetParameter($key);

    /**
     * @return array
     */
    public function getMetadatas();

    /**
     * @param array $metadatas
     */
    public function setMetadatas(array $metadatas);

    /**
     * @param string $key
     * @param mixed $value
     *
     * @return mixed
     */
    public function setMetadata($key, $value);

    /**
     * @param string $key
     */
    public function getMetadata($key);

    /**
     * @param string $key
     */
    public function hasMetadata($key);

    /**
     * @param string $key
     */
    public function unsetMetadata($key);
}
