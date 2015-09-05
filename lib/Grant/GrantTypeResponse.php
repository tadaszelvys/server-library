<?php

namespace OAuth2\Grant;

class GrantTypeResponse implements GrantTypeResponseInterface
{
    /**
     * @var array
     */
    protected $additional_data = [];

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
    protected $client_public_id;

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
     * {@inheritdoc}
     */
    public function setAdditionalData($key, $data)
    {
        $this->additional_data[$key] = $data;

        return $this;
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
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function setClientPublicId($client_public_id)
    {
        $this->client_public_id = $client_public_id;

        return $this;
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
     * {@inheritdoc}
     */
    public function setRefreshTokenRevoked($revoke_refresh_token = null)
    {
        $this->revoke_refresh_token = $revoke_refresh_token;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getRefreshTokenRevoked()
    {
        return $this->revoke_refresh_token;
    }
}
