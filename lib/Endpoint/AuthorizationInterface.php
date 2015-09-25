<?php

namespace OAuth2\Endpoint;

use OAuth2\Client\ClientInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AuthorizationInterface
{
    /**
     * @return \OAuth2\Client\ClientInterface The client
     */
    public function getClient();

    /**
     * @return string The response type
     */
    public function getResponseType();

    /**
     * @return string|null The redirect uri
     */
    public function getRedirectUri();

    /**
     * @return \OAuth2\ResourceOwner\ResourceOwnerInterface|null The resource owner
     */
    public function getResourceOwner();

    /**
     * @return string[] An array of ScopeInterface objects
     */
    public function getScope();

    /**
     * Set the scope of the authorization object. This setter is needed if the requested scope is not compliant with the scope policy.
     *
     * @param string[] $scope An array of ScopeInterface objects
     *
     * @return self
     */
    public function setScope(array $scope);

    /**
     * @return string|null The state
     */
    public function getState();

    /**
     * @return bool A refresh token is asked by the client
     */
    public function getIssueRefreshToken();

    /**
     * @return bool The resource owner authorized the client
     */
    public function isAuthorized();

    /**
     * @return string The response mode
     */
    public function getResponseMode();

    /**
     * @param \OAuth2\Client\ClientInterface $client
     *
     * @return $this
     */
    public function setClient(ClientInterface $client);

    /**
     * @param string $response_type
     *
     * @return $this
     */
    public function setResponseType($response_type);

    /**
     * @param string $redirect_uri
     *
     * @return $this
     */
    public function setRedirectUri($redirect_uri);

    /**
     * @param \OAuth2\ResourceOwner\ResourceOwnerInterface $resource_owner
     *
     * @return $this
     */
    public function setResourceOwner(ResourceOwnerInterface $resource_owner);

    /**
     * @param string $state
     *
     * @return $this
     */
    public function setState($state);

    /**
     * @param bool $issue_refresh_token
     *
     * @return $this
     */
    public function setIssueRefreshToken($issue_refresh_token);

    /**
     * @param bool $authorized
     *
     * @return $this
     */
    public function setAuthorized($authorized);

    /**
     * @param string $response_mode
     *
     * @return $this
     */
    public function setResponseMode($response_mode);

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return \OAuth2\Endpoint\Authorization
     */
    public static function createFromRequest(ServerRequestInterface $request);
}
