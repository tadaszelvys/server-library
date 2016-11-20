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

class SoftwareRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function check(ClientInterface $client, array $registration_parameters)
    {
        foreach (['software_id', 'software_version', 'software_statement'] as $key) {
            if (array_key_exists($key, $registration_parameters)) {
                $client->set($key, $registration_parameters[$key]);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getPreserverParameters()
    {
        return [];
    }
}
