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

use Assert\Assertion;
use OAuth2\Client\Rule\RuleManagerInterface;

trait HasClientRuleManager
{
    /**
     * @var \OAuth2\Client\Rule\RuleManagerInterface|null
     */
    private $client_rule_manager = null;

    /**
     * @return bool
     */
    protected function hasClientRuleManager()
    {
        return null !== $this->client_rule_manager;
    }

    /**
     * @return \OAuth2\Client\Rule\RuleManagerInterface
     */
    protected function getClientRuleManager()
    {
        Assertion::true($this->hasClientRuleManager(), 'The client rule manager is not available.');

        return $this->client_rule_manager;
    }

    /**
     * @param \OAuth2\Client\Rule\RuleManagerInterface $client_rule_manager
     */
    protected function setClientRuleManager(RuleManagerInterface $client_rule_manager)
    {
        $this->client_rule_manager = $client_rule_manager;
    }
}
