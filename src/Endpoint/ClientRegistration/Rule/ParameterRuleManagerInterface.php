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

interface ParameterRuleManagerInterface
{
    /**
     * @param \OAuth2\Endpoint\ClientRegistration\Rule\ParameterRuleInterface $client_registration_rule
     */
    public function addParameterRule(ParameterRuleInterface $client_registration_rule);

    /**
     * @return \OAuth2\Endpoint\ClientRegistration\Rule\ParameterRuleInterface[]
     */
    public function getParameterRules();
}
