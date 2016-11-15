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

class RuleManager implements RuleManagerInterface
{
    /**
     * @var \OAuth2\Client\Rule\RuleInterface[]
     */
    private $rules = [];

    /**
     * {@inheritdoc}
     */
    public function processParametersForClient(ClientInterface $client, array $parameters)
    {
        foreach ($this->rules as $rule) {
            $rule->check($client, $parameters);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function addRule(RuleInterface $rule)
    {
        $this->rules[] = $rule;
    }
}
