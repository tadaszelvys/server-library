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

final class ClientRegistrationRuleManager implements ClientRegistrationRuleManagerInterface
{
    /**
     * @var \OAuth2\Endpoint\ClientRegistration\Rule\ClientRegistrationRuleInterface[]
     */
    private $client_registration_rules = [];

    /**
     * {@inheritdoc}
     */
    public function addClientRegistrationRule(ClientRegistrationRuleInterface $client_registration_rule)
    {
        $this->client_registration_rules[] = $client_registration_rule;
    }

    /**
     * {@inheritdoc}
     */
    public function getClientRegistrationRules()
    {
        return $this->client_registration_rules;
    }
}
