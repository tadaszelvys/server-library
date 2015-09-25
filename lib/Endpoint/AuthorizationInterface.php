<?php

namespace OAuth2\Endpoint;

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
     * @return \OAuth2\Scope\ScopeInterface[] An array of ScopeInterface objects
     */
    public function getScope();

    /**
     * Set the scope of the authorization object. This setter is needed if the requested scope is not compliant with the scope policy.
     *
     * @param \OAuth2\Scope\ScopeInterface[] $scope An array of ScopeInterface objects
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
}
