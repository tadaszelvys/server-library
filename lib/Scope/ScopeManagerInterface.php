<?php

namespace OAuth2\Scope;

use OAuth2\Client\ClientInterface;
use Symfony\Component\HttpFoundation\Request;

interface ScopeManagerInterface
{
    const POLICY_MODE_ERROR = 'error';
    const POLICY_MODE_DEFAULT = 'default';

    /**
     * This function returns the available scopes. If a valid ClientInterface object is set as parameter, the function will return available scopes for the client.
     * The request object is sent to the client to allow the client to have different scopes and scope policy depending on the grant type for example.
     *
     * @param \OAuth2\Client\ClientInterface            $client  A client
     * @param \Symfony\Component\HttpFoundation\Request $request The request
     *
     * @return \OAuth2\Scope\ScopeInterface[] Return an array ScopeInterface objects
     */
    public function getAvailableScopes(ClientInterface $client = null, Request $request = null);

    /**
     * This function returns the default scopes. If a valid ClientInterface object is set as parameter, the function will return default scopes for the client.
     * The request object is sent to the client to allow the client to have different scopes and scope policy depending on the grant type for example.
     *
     * @param \OAuth2\Client\ClientInterface            $client  A client
     * @param \Symfony\Component\HttpFoundation\Request $request The request
     *
     * @return \OAuth2\Scope\ScopeInterface[] Return an array ScopeInterface objects
     */
    public function getDefaultScopes(ClientInterface $client = null, Request $request = null);

    /**
     * This function returns the scope policy. If a valid ClientInterface object is set as parameter, the function will return scope policy for the client.
     * The request object is sent to the client to allow the client to have different scopes and scope policy depending on the grant type for example.
     *
     * @param \OAuth2\Client\ClientInterface            $client  A client
     * @param \Symfony\Component\HttpFoundation\Request $request The request
     *
     * @return string Return "default" or "error" depending on the configuration
     */
    public function getScopePolicy(ClientInterface $client = null, Request $request = null);

    /**
     * This function check if the scopes respect the scope policy for the client.
     *
     * @param \OAuth2\Client\ClientInterface            $client  A client
     * @param \OAuth2\Scope\ScopeInterface[]            $scope   The scopes
     * @param \Symfony\Component\HttpFoundation\Request $request The request
     *
     * @return \OAuth2\Scope\ScopeInterface[] An array ScopeInterface objects according to the scope policy
     */
    public function checkScopePolicy(ClientInterface $client, array $scope, Request $request = null);

    /**
     * @param ScopeInterface[] $requestedScopes An array of ScopeInterface objects that represents requested scopes
     * @param ScopeInterface[] $availableScopes An array of ScopeInterface objects that represents available scopes
     *
     * @return bool Return true if the requested scope is within the available scope
     */
    public function checkScopes(array $requestedScopes, array $availableScopes);

    /**
     * Convert a string that contains at least one scope to an array of ScopeInterface objects.
     *
     * @param null|string|string[]|\OAuth2\Scope\ScopeInterface[] $scope The string to convert
     *
     * @return \OAuth2\Scope\ScopeInterface[] An array of ScopeInterface objects
     *
     * @throws \Exception If the string contains forbidden characters or if the scope is unknown.
     */
    public function convertToScope($scope);
}
