<?php

namespace OAuth2\Endpoint;

use OAuth2\Client\ClientInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;

class Authorization implements AuthorizationInterface
{
    /**
     * @var null|\OAuth2\Client\ClientInterface
     */
    protected $client = null;

    /**
     * @var null|string
     */
    protected $response_type = null;

    /**
     * @var null|string
     */
    protected $redirect_uri = null;

    /**
     * @var null|\OAuth2\ResourceOwner\ResourceOwnerInterface
     */
    protected $resource_owner = null;

    /**
     * @var \OAuth2\Scope\ScopeInterface[]
     */
    protected $scope = [];

    /**
     * @var null|string
     */
    protected $state = null;

    /**
     * @var bool
     */
    protected $issue_refresh_token = false;

    /**
     * @var bool
     */
    protected $authorized = false;

    /**
     * {@inheritdoc}
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @return $this
     */
    public function setClient(ClientInterface $client)
    {
        $this->client = $client;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return $this->response_type;
    }

    /**
     * @param string $response_type
     *
     * @return $this
     */
    public function setResponseType($response_type)
    {
        $this->response_type = $response_type;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getRedirectUri()
    {
        return $this->redirect_uri;
    }

    /**
     * @param string $redirect_uri
     *
     * @return $this
     */
    public function setRedirectUri($redirect_uri)
    {
        $this->redirect_uri = $redirect_uri;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getResourceOwner()
    {
        return $this->resource_owner;
    }

    /**
     * @param \OAuth2\ResourceOwner\ResourceOwnerInterface $resource_owner
     *
     * @return $this
     */
    public function setResourceOwner(ResourceOwnerInterface $resource_owner)
    {
        $this->resource_owner = $resource_owner;

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
     * {@inheritdoc}
     */
    public function setScope(array $scope)
    {
        $this->scope = $scope;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getState()
    {
        return $this->state;
    }

    /**
     * @param string $state
     *
     * @return $this
     */
    public function setState($state)
    {
        $this->state = $state;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getIssueRefreshToken()
    {
        return $this->issue_refresh_token;
    }

    /**
     * @param bool $issue_refresh_token
     *
     * @return $this
     */
    public function setIssueRefreshToken($issue_refresh_token)
    {
        $this->issue_refresh_token = $issue_refresh_token;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthorized()
    {
        return $this->authorized;
    }

    /**
     * @param bool $authorized
     *
     * @return $this
     */
    public function setAuthorized($authorized)
    {
        $this->authorized = $authorized;

        return $this;
    }
}
