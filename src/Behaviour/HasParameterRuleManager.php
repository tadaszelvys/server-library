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
use OAuth2\Endpoint\ClientRegistration\Rule\ParameterRuleManagerInterface;

trait HasParameterRuleManager
{
    /**
     * @var \OAuth2\Endpoint\ClientRegistration\Rule\ParameterRuleManagerInterface|null
     */
    private $parameter_rule_manager = null;

    /**
     * @return bool
     */
    protected function hasParameterRuleManager()
    {
        return null !== $this->parameter_rule_manager;
    }

    /**
     * @return \OAuth2\Endpoint\ClientRegistration\Rule\ParameterRuleManagerInterface
     */
    protected function getParameterRuleManager()
    {
        Assertion::true($this->hasParameterRuleManager(), 'The parameter rule manager is not available.');

        return $this->parameter_rule_manager;
    }

    /**
     * @param \OAuth2\Endpoint\ClientRegistration\Rule\ParameterRuleManagerInterface $parameter_rule_manager
     */
    protected function setParameterRuleManager(ParameterRuleManagerInterface $parameter_rule_manager)
    {
        $this->parameter_rule_manager = $parameter_rule_manager;
    }
}
