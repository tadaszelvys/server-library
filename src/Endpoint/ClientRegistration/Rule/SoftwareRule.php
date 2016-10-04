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

final class SoftwareRule implements ParameterRuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkParameters(array $registration_parameters, array &$metadatas, array $previous_metadata = [])
    {
        foreach (['software_id', 'software_version', 'software_statement'] as $key) {
            if (array_key_exists($key, $registration_parameters)) {
                $metadatas[$key] = $registration_parameters[$key];
            }
        }
    }
}
