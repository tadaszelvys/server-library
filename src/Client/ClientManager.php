<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

use Base64Url\Base64Url;
use OAuth2\Client\Rule\RuleInterface;

abstract class ClientManager implements ClientManagerInterface
{
    /**
     * @var \OAuth2\Client\Rule\RuleInterface[]
     */
    private $rules = [];

    /**
     * {@inheritdoc}
     */
    public function createClient()
    {
        $client = new Client();
        $client->set('client_id_issued_at', time());

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    public function createClientFromParameters(array $parameters)
    {
        $client = $this->createClient();
        foreach ($this->rules as $rule) {
            $rule->check($client, $parameters);
        }

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    public function addRule(RuleInterface $rule)
    {
        $this->rules[] = $rule;
    }

    /**
     * {@inheritdoc}
     */
    public function getRules()
    {
        return $this->rules;
    }
}
