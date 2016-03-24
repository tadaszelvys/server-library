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

interface ScopePolicyInterface
{
    /**
     * @return string
     */
    public function getName();

    /**
     * This function check if the scopes respect the scope policy for the client.
     *
     * @param string[]                                 $scope   The scopes. This variable may be modified according to the scope policy
     * @param \OAuth2\Client\ClientInterface           $client  The client
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     */
    public function checkScopePolicy(array &$scope, ClientInterface $client, ServerRequestInterface $request = null);
}
