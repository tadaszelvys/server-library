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

use OAuth2\Client\Rule\RuleInterface;
use Psr\Http\Message\ServerRequestInterface;

interface ClientManagerInterface
{
    /**
     * @param \OAuth2\Client\Rule\RuleInterface $rule
     */
    public function addRule(RuleInterface $rule);

    /**
     * @return \OAuth2\Client\Rule\RuleInterface[]
     */
    public function getRules();

    /**
     * @return \OAuth2\Client\ClientInterface Return a new client object.
     */
    public function createClient();

    /**
     * @param array $parameters
     *
     * @return \OAuth2\Client\ClientInterface
     */
    public function createClientFromParameters(array $parameters);

    /**
     * Get a client using its Id.
     *
     * @param string $client_id The Id of the client
     *
     * @return null|\OAuth2\Client\ClientInterface Return the client object or null if no client is found.
     */
    public function getClient($client_id);

    /**
     * Save the client.
     *
     * @param \OAuth2\Client\ClientInterface $client
     */
    public function saveClient(ClientInterface $client);
}
