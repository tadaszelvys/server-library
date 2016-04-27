<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use OAuth2\Token\RefreshTokenInterface;

interface GrantTypeResponseInterface
{
    /**
     * @return string|null
     */
    public function getRedirectUri();

    /**
     * @param string $redirect_uri
     */
    public function setRedirectUri($redirect_uri);
    
    /**
     * @param string $key
     *
     * @return mixed
     */
    public function getAdditionalData($key);

    /**
     * @param string $key
     * @param mixed  $data
     */
    public function setAdditionalData($key, $data);

    /**
     * The scope requested.
     *
     * @return string[]
     */
    public function getRequestedScope();

    /**
     * @param string[] $requested_scope
     */
    public function setRequestedScope(array $requested_scope);

    /**
     * The scope available.
     *
     * @return null|string[]
     */
    public function getAvailableScope();

    /**
     * @param string[] $available_scope
     */
    public function setAvailableScope(array $available_scope);

    /**
     * @return string
     */
    public function getClientPublicId();

    /**
     * @param string $client_owner_public_id
     */
    public function setClientPublicId($client_owner_public_id);

    /**
     * The resource owner associated with the access token.
     * It could be a user (for Implicit grant type or Resource Owner Password Credentials grant type) or a client_public_id (for Client Credentials grant type).
     *
     * @return string
     */
    public function getResourceOwnerPublicId();

    /**
     * @param string $resource_owner_public_id
     */
    public function setResourceOwnerPublicId($resource_owner_public_id);

    /**
     * @return bool If true, a refresh token is requested
     */
    public function isRefreshTokenIssued();

    /**
     * @param bool $issue_refresh_token
     */
    public function setRefreshTokenIssued($issue_refresh_token);

    /**
     * @return string[]
     */
    public function getRefreshTokenScope();

    /**
     * @param string[] $refresh_token_scope
     */
    public function setRefreshTokenScope(array $refresh_token_scope);

    /**
     * @return \OAuth2\Token\RefreshTokenInterface|null If not null, the refresh token will be revoked
     */
    public function getRefreshTokenRevoked();

    /**
     * @param \OAuth2\Token\RefreshTokenInterface $revoke_refresh_token
     */
    public function setRefreshTokenRevoked(RefreshTokenInterface $revoke_refresh_token);
}
