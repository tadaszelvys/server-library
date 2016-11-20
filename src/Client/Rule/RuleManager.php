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
     * @var string[]
     */
    private $preserved_parameters = ['client_id_issued_at'];

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
    public function getPreserverParameters()
    {
        return $this->preserved_parameters;
    }

    /**
     * {@inheritdoc}
     */
    public function addRule(RuleInterface $rule)
    {
        $this->rules[] = $rule;
        $this->preserved_parameters = array_unique(array_merge(
            $rule->getPreserverParameters(),
            $this->preserved_parameters
        ));
    }
}
