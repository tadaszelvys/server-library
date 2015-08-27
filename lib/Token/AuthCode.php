<?php

namespace OAuth2\Token;

class AuthCode implements AuthCodeInterface
{
    /**
     * @var array
     */
    private $scope;

    /**
     * @var string
     */
    private $code;

    /**
     * @var string
     */
    private $client_public_id;

    /**
     * @var int
     */
    private $expires_at;

    /**
     * @var null|\OAuth2\ResourceOwner\ResourceOwnerInterface
     */
    private $resource_owner_public_id;

    /**
     * @var bool|false
     */
    private $issue_refresh_token;

    /**
     * @var string
     */
    private $redirect_uri;

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
    public function getCode()
    {
        return $this->code;
    }

    /**
     * @param string $code
     *
     * @return self
     */
    public function setCode($code)
    {
        $this->code = $code;

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
     * {@inheritdoc}
     */
    public function getIssueRefreshToken()
    {
        return $this->issue_refresh_token;
    }

    /**
     * @param bool $issue_refresh_token
     *
     * @return self
     */
    public function setIssueRefreshToken($issue_refresh_token)
    {
        $this->issue_refresh_token = $issue_refresh_token;

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
     * @return self
     */
    public function setRedirectUri($redirect_uri)
    {
        $this->redirect_uri = $redirect_uri;

        return $this;
    }
}
