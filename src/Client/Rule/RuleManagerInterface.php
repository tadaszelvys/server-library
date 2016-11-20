<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client\Rule;

use OAuth2\Client\ClientInterface;

interface RuleManagerInterface
{
    /**
     * @param \OAuth2\Client\Rule\RuleInterface $rule
     */
    public function addRule(RuleInterface $rule);

    /**
     * @param \OAuth2\Client\ClientInterface $client
     * @param array                          $parameters
     */
    public function processParametersForClient(ClientInterface $client, array $parameters);

    /**
     * @return string[]
     */
    public function getPreserverParameters();
}
