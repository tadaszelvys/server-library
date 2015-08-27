<?php

namespace OAuth2\Test\Stub;

use OAuth2\Token\RefreshTokenInterface;

class RefreshToken implements RefreshTokenInterface
{
    /**
     * @var bool
     */
    private $used;

    /**
     * @var \OAuth2\Scope\ScopeInterface[]
     */
    private $scope;

    /**
     * @var string
     */
    private $token;

    /**
     * @var string
     */
    private $client_public_id;

    /**
     * @var int
     */
    private $expires_at;

    /**
     * @var null|string
     */
    private $resource_owner_public_id;

    /**
     * {@inheritdoc}
     */
    public function getClientPublicId()
    {
        return $this->client_public_id;
    }

    /**
     * @param string $client_public_id
     *
     * @return self
     */
    public function setClientPublicId($client_public_id)
    {
        $this->client_public_id = $client_public_id;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * @param string $token
     *
     * @return self
     */
    public function setToken($token)
    {
        $this->token = $token;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * @param array $scope
     *
     * @return self
     */
    public function setScope(array $scope)
    {
        $this->scope = $scope;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwnerPublicId()
    {
        return $this->resource_owner_public_id;
    }

    /**
     * @param string|null $resource_owner_public_id
     *
     * @return self
     */
    public function setResourceOwnerPublicId($resource_owner_public_id)
    {
        $this->resource_owner_public_id = $resource_owner_public_id;

        return $this;
    }

    /**
     * @return int
     */
    public function getExipresAt()
    {
        return $this->expires_at;
    }

    /**
     * @param int $expires_at
     *
     * @return self
     */
    public function setExipresAt($expires_at)
    {
        $this->expires_at = $expires_at;

        return $this;
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

    /**
     * @return bool
     */
    public function isUsed()
    {
        return $this->used;
    }

    /**
     * @param bool $used
     *
     * @return self
     */
    public function setUsed($used)
    {
        $this->used = $used;

        return $this;
    }
}
