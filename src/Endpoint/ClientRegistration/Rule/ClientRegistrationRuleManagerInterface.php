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

interface ClientRegistrationRuleManagerInterface
{
    /**
     * @param \OAuth2\Endpoint\ClientRegistration\Rule\ClientRegistrationRuleInterface $client_registration_rule
     */
    public function addClientRegistrationRule(ClientRegistrationRuleInterface $client_registration_rule);

    /**
     * @return \OAuth2\Endpoint\ClientRegistration\Rule\ClientRegistrationRuleInterface[]
     */
    public function getClientRegistrationRules();
}
