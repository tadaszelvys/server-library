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
     * @var array|null
     */
    private $additional_data = [];

    /**
     * @var string[]
     */
    private $requested_scope = [];

    /**
     * @var null|string[]
     */
    private $available_scope = null;

    /**
     * @var string
     */
    private $resource_owner_public_id;

    /**
     * @var string
     */
    private $client_public_id;

    /**
     * @var bool
     */
    private $issue_refresh_token = false;

    /**
     * @var null|string[]
     */
    private $refresh_token_scope = [];

    /**
     * @var \OAuth2\Token\RefreshTokenInterface
     */
    private $revoke_refresh_token = null;

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
    public function setRequestedScope(array $requested_scope)
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
    public function setAvailableScope(array $available_scope)
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
    public function setRefreshTokenScope(array $refresh_token_scope)
    {
        $this->refresh_token_scope = $refresh_token_scope;
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
