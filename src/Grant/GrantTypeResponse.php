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

final class GrantTypeResponse implements GrantTypeResponseInterface
{
    /**
     * @var array
     */
    private $additional_data = null;

    /**
     * @var
     */
    private $requested_scope = null;

    /**
     * @var
     */
    private $available_scope = null;

    /**
     * @var
     */
    private $resource_owner_public_id = null;

    /**
     * @var
     */
    private $client_public_id = null;

    /**
     * @var
     */
    private $issue_refresh_token = false;

    /**
     * @var
     */
    private $refresh_token_scope = null;

    /**
     * @var \OAuth2\Token\RefreshTokenInterface
     */
    private $revoke_refresh_token = null;

    /**
     * @var
     */
    private $issue_id_token = false;

    /**
     * @var
     */
    private $auth_code = null;

    /**
     * {@inheritdoc}
     */
    public function setAdditionalData($key, $data)
    {
        $this->additional_data[$key] = $data;
    }

    /**
     * {@inheritdoc}
     */
    public function getAdditionalData($key)
    {
        return array_key_exists($key, $this->additional_data) ? $this->additional_data[$key] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function setRequestedScope($requested_scope = null)
    {
        $this->requested_scope = $requested_scope;
    }

    /**
     * {@inheritdoc}
     */
    public function getRequestedScope()
    {
        return $this->requested_scope;
    }

    /**
     * {@inheritdoc}
     */
    public function setAvailableScope($available_scope)
    {
        $this->available_scope = $available_scope;
    }

    /**
     * {@inheritdoc}
     */
    public function getAvailableScope()
    {
        return $this->available_scope;
    }

    /**
     * {@inheritdoc}
     */
    public function setClientPublicId($client_public_id)
    {
        $this->client_public_id = $client_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function getClientPublicId()
    {
        return $this->client_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function setResourceOwnerPublicId($resource_owner_public_id = null)
    {
        $this->resource_owner_public_id = $resource_owner_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerPublicId()
    {
        return $this->resource_owner_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function setRefreshTokenIssued($issue_refresh_token = false)
    {
        $this->issue_refresh_token = $issue_refresh_token;
    }

    /**
     * {@inheritdoc}
     */
    public function isRefreshTokenIssued()
    {
        return $this->issue_refresh_token;
    }

    /**
     * {@inheritdoc}
     */
    public function setRefreshTokenScope($refresh_token_scope = null)
    {
        $this->refresh_token_scope = $refresh_token_scope;
    }

    /**
     * {@inheritdoc}
     */
    public function setIdTokenIssued($issue_id_token)
    {
        $this->issue_id_token = $issue_id_token;
    }

    /**
     * {@inheritdoc}
     */
    public function isIdTokenIssued()
    {
        return $this->issue_id_token;
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthorizationCodeToHash($auth_code)
    {
        $this->auth_code = $auth_code;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationCodeToHash()
    {
        return $this->auth_code;
    }

    /**
     * {@inheritdoc}
     */
    public function getRefreshTokenScope()
    {
        return $this->refresh_token_scope;
    }

    /**
     * {@inheritdoc}
     */
    public function setRefreshTokenRevoked(RefreshTokenInterface $revoke_refresh_token = null)
    {
        $this->revoke_refresh_token = $revoke_refresh_token;
    }

    /**
     * {@inheritdoc}
     */
    public function getRefreshTokenRevoked()
    {
        return $this->revoke_refresh_token;
    }
}
