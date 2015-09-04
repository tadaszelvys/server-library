<?php

namespace OAuth2\Grant;

use OAuth2\Token\RefreshTokenInterface;

class GrantTypeResponse implements GrantTypeResponseInterface
{
    /**
     * @var
     */
    protected $requested_scope;

    /**
     * @var
     */
    protected $available_scope;

    /**
     * @var
     */
    protected $resource_owner_public_id;

    /**
     * @var
     */
    protected $issue_refresh_token;

    /**
     * @var
     */
    protected $refresh_token_scope;

    /**
     * @var
     */
    protected $revoke_refresh_token;

    /**
     * @param string[]|string|null $requested_scope
     *
     * @return self
     */
    public function setRequestedScope($requested_scope = null)
    {
        $this->requested_scope = $requested_scope;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getRequestedScope()
    {
        return $this->requested_scope;
    }

    /**
     * @param string[]|string|null $available_scope
     *
     * @return self
     */
    public function setAvailableScope($available_scope = null)
    {
        $this->available_scope = $available_scope;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getAvailableScope()
    {
        return $this->available_scope;
    }

    /**
     * @param string|null $resource_owner_public_id
     *
     * @return self
     */
    public function setResourceOwnerPublicId($resource_owner_public_id = null)
    {
        $this->resource_owner_public_id = $resource_owner_public_id;

        return $this;
    }

    /**
     * @return string|null
     */
    public function getResourceOwnerPublicId()
    {
        return $this->resource_owner_public_id;
    }

    /**
     * @param bool $issue_refresh_token
     *
     * @return self
     */
    public function setRefreshTokenIssued($issue_refresh_token = false)
    {
        $this->issue_refresh_token = $issue_refresh_token;

        return $this;
    }

    /**
     * @return bool
     */
    public function isRefreshTokenIssued()
    {
        return $this->issue_refresh_token;
    }

    /**
     * @param string[]|string[]|string|null $refresh_token_scope
     *
     * @return self
     */
    public function setRefreshTokenScope($refresh_token_scope = null)
    {
        $this->refresh_token_scope = $refresh_token_scope;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getRefreshTokenScope()
    {
        return $this->refresh_token_scope;
    }

    /**
     * @param \OAuth2\Token\RefreshTokenInterface|null $revoke_refresh_token
     *
     * @return self
     */
    public function setRefreshTokenRevoked(RefreshTokenInterface $revoke_refresh_token = null)
    {
        $this->revoke_refresh_token = $revoke_refresh_token;

        return $this;
    }

    /**
     * @return \OAuth2\Token\RefreshTokenInterface|null
     */
    public function getRefreshTokenRevoked()
    {
        return $this->revoke_refresh_token;
    }
}
