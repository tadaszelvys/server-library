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

final class ParameterRuleManager implements ParameterRuleManagerInterface
{
    /**
     * @var \OAuth2\Endpoint\ClientRegistration\Rule\ParameterRuleInterface[]
     */
    private $parameter_rules = [];

    /**
     * {@inheritdoc}
     */
    public function addParameterRule(ParameterRuleInterface $parameter_rule)
    {
        $this->parameter_rules[] = $parameter_rule;
    }

    /**
     * {@inheritdoc}
     */
    public function getParameterRules()
    {
        return $this->parameter_rules;
    }
}
