<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\ClientRegistration\Rule;

use OAuth2\Client\ClientInterface;

interface ParameterRuleInterface
{
    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $registration_parameters
     * @param array                          $metadatas
     *
     * @throws \InvalidArgumentException If an error occurred
     */
    public function checkParameters(ClientInterface $client, array $registration_parameters, array &$metadatas);
}
