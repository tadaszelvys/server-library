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
     * @return string[]|string|null
     */
    public function getRequestedScope();

    /**
     * @param string[]|string|null $requested_scope
     */
    public function setRequestedScope($requested_scope);

    /**
     * The scope available.
     *
     * @return string[]|string|null
     */
    public function getAvailableScope();

    /**
     * @param string[]|string|null $available_scope
     */
    public function setAvailableScope($available_scope);

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
     * @return string|null
     */
    public function getResourceOwnerPublicId();

    /**
     * @param string|null $resource_owner_public_id
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
     * @return bool If true, an Id token will be issued with the access token
     */
    public function isIdTokenIssued();

    /**
     * @param bool $issue_id_token
     */
    public function setIdTokenIssued($issue_id_token);

    /**
     * @return string|null
     */
    public function getAuthorizationCodeToHash();

    /**
     * @param string $auth_code
     */
    public function setAuthorizationCodeToHash($auth_code);

    /**
     * @return string[]|string|null If not null, a refresh token will be issued using the scope returned
     */
    public function getRefreshTokenScope();

    /**
     * @param string[]|string[]|string|null $refresh_token_scope
     */
    public function setRefreshTokenScope($refresh_token_scope);

    /**
     * @return \OAuth2\Token\RefreshTokenInterface|null If not null, the refresh token will be revoked
     */
    public function getRefreshTokenRevoked();

    /**
     * @param \OAuth2\Token\RefreshTokenInterface|null $revoke_refresh_token
     */
    public function setRefreshTokenRevoked(RefreshTokenInterface $revoke_refresh_token);
}
