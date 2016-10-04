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

interface ParameterRuleInterface
{
    /**
     * @param array $registration_parameters
     * @param array $metadatas
     * @param array $previous_metadata
     *
     * @throws \InvalidArgumentException If an error occurred
     */
    public function checkParameters(array $registration_parameters, array &$metadatas, array $previous_metadata = []);
}
