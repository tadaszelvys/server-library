<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

use OAuth2\Endpoint\ClientRegistration\Rule\ClientRegistrationRuleManagerInterface;

trait HasClientRegistrationRuleManager
{
    /**
     * @var \OAuth2\Endpoint\ClientRegistration\Rule\ClientRegistrationRuleManagerInterface
     */
    private $client_registration_rule_manager;

    /**
     * @return \OAuth2\Endpoint\ClientRegistration\Rule\ClientRegistrationRuleManagerInterface
     */
    private function getClientRegistrationRuleManager()
    {
        return $this->client_registration_rule_manager;
    }

    /**
     * @param \OAuth2\Endpoint\ClientRegistration\Rule\ClientRegistrationRuleManagerInterface $client_registration_rule_manager
     */
    private function setClientRegistrationRuleManager(ClientRegistrationRuleManagerInterface $client_registration_rule_manager)
    {
        $this->client_registration_rule_manager = $client_registration_rule_manager;
    }
}
