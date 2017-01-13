<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\Scope;

use OAuth2\Model\Client\Client;

interface ScopePolicyInterface
{
    /**
     * @return string
     */
    public function name(): string;

    /**
     * This function check if the scopes respect the scope policy for the client.
     *
     * @param string[] $scope  The scopes. This variable may be modified according to the scope policy
     * @param Client   $client The client
     */
    public function checkScopePolicy(array &$scope, Client $client);
}
