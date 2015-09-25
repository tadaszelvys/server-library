<?php

namespace OAuth2\Endpoint;

use OAuth2\Client\ClientInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use Psr\Http\Message\ServerRequestInterface;

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
     * @var array
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
     * @var null|string
     */
    protected $response_mode = null;

    /**
     * {@inheritdoc}
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
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
     * {@inheritdoc}
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
     * {@inheritdoc}
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
     * {@inheritdoc}
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
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function setAuthorized($authorized)
    {
        $this->authorized = $authorized;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode()
    {
        return $this->response_mode;
    }

    /**
     * {@inheritdoc}
     */
    public function setResponseMode($response_mode)
    {
        $this->response_mode = $response_mode;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public static function createFromRequest(ServerRequestInterface $request)
    {
        $params = $request->getQueryParams();
        $authorization = new Authorization();
        $methods = [
            'setRedirectUri'  => 'redirect_uri',
            'setResponseMode' => 'response_mode',
            'setResponseType' => 'response_type',
            'setScope'        => 'scope',
            'setState'        => 'state',
        ];

        foreach($methods as $method=>$param) {
            $authorization->$method(isset($params['$param'])?$params['$param']:null);
        }

        return $authorization;
    }
}
