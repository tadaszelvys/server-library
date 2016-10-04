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

use Assert\Assertion;

final class RequestUriRule implements ParameterRuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkParameters(array $registration_parameters, array &$metadatas, array $previous_metadata = [])
    {
        if (!array_key_exists('request_uris', $registration_parameters)) {
            return;
        }
        Assertion::isArray($registration_parameters['request_uris'], 'The parameter "request_uris" must be a list of URI.');
        Assertion::allUrl($registration_parameters['request_uris'], 'The parameter "request_uris" must be a list of URI.');
    }
}
