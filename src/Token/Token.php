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

class Token implements TokenInterface
{
    /**
     * @var array
     */
    protected $scope;

    /**
     * @var string
     */
    protected $token;

    /**
     * @var string
     */
    protected $client_public_id;

    /**
     * @var int
     */
    protected $expires_at;

    /**
     * @var string
     */
    protected $resource_owner_public_id;

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
    public function setClientPublicId($client_public_id)
    {
        $this->client_public_id = $client_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * {@inheritdoc}
     */
    public function setToken($token)
    {
        $this->token = $token;
    }

    /**
     * {@inheritdoc}
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * {@inheritdoc}
     */
    public function setScope(array $scope)
    {
        $this->scope = $scope;
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
    public function setResourceOwnerPublicId($resource_owner_public_id)
    {
        $this->resource_owner_public_id = $resource_owner_public_id;
    }

    /**
     * {@inheritdoc}
     */
    public function getExpiresAt()
    {
        return $this->expires_at;
    }

    /**
     * {@inheritdoc}
     */
    public function setExpiresAt($expires_at)
    {
        $this->expires_at = $expires_at;
    }

    /**
     * {@inheritdoc}
     */
    public function hasExpired()
    {
        return $this->expires_at < time();
    }

    /**
     * {@inheritdoc}
     */
    public function getExpiresIn()
    {
        return $this->expires_at - time() < 0 ? 0 : $this->expires_at - time();
    }
}
