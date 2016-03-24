<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Scope;

use OAuth2\Client\ClientInterface;
use Psr\Http\Message\ServerRequestInterface;

interface ScopeManagerInterface
{
    /**
     * @param \OAuth2\Scope\ScopePolicyInterface $scope_policy
     * @param bool                               $is_default
     */
    public function addScopePolicy(ScopePolicyInterface $scope_policy, $is_default = false);

    /**
     * This function returns the available scopes. If a valid ClientInterface object is set as parameter, the function will return available scopes for the client.
     * The request object is sent to the client to allow the client to have different scopes and scope policy depending on the grant type for example.
     *
     * @param \OAuth2\Client\ClientInterface           $client  A client
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     *
     * @return string[] Return an array scope
     */
    public function getAvailableScopesForClient(ClientInterface $client, ServerRequestInterface $request = null);

    /**
     * This function returns the scope policy. If a valid ClientInterface object is set as parameter, the function will return scope policy for the client.
     * The request object is sent to the client to allow the client to have different scopes and scope policy depending on the grant type for example.
     *
     * @param \OAuth2\Client\ClientInterface           $client  A client
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     *
     * @return string Return "default" or "error" depending on the configuration
     */
    public function getScopePolicyForClient(ClientInterface $client, ServerRequestInterface $request = null);

    /**
     * This function check if the scopes respect the scope policy for the client.
     *
     * @param string[]                                 $scope   The scopes
     * @param \OAuth2\Client\ClientInterface           $client  A client
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     *
     * @return string[] An array scopes according to the scope policy
     */
    public function checkScopePolicy(array $scope, ClientInterface $client, ServerRequestInterface $request = null);

    /**
     * @param string[] $requestedScopes An array of scopes that represents requested scopes
     * @param string[] $availableScopes An array of scopes that represents available scopes
     *
     * @return bool Return true if the requested scope is within the available scope
     */
    public function checkScopes(array $requestedScopes, array $availableScopes);

    /**
     * Convert a string that contains at least one scope to an array of scopes.
     *
     * @param string $scope The string to convert
     *
     * @return string[] An array of scopes
     */
    public function convertToArray($scope);
}
