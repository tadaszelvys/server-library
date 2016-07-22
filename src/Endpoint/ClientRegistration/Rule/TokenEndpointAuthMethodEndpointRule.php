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
use OAuth2\Behaviour\HasTokenEndpointAuthMethod;

final class TokenEndpointAuthMethodEndpointRule implements ClientRegistrationRuleInterface
{
    use HasTokenEndpointAuthMethod;

    /**
     * {@inheritdoc}
     */
    public function checkRegistrationParameters(array $registration_parameters, array &$additional_metadatas)
    {
        Assertion::keyExists($registration_parameters, 'token_endpoint_auth_method', 'The parameter "token_endpoint_auth_method" is missing.');
        Assertion::string($registration_parameters['token_endpoint_auth_method'], 'The parameter "token_endpoint_auth_method" must be a string.');
        Assertion::inArray($registration_parameters['token_endpoint_auth_method'], $this->getSupportedAuthenticationMethods(), sprintf('The token endpoint authentication method "%s" is not supported. Please use one of the following values: %s', $registration_parameters['token_endpoint_auth_method'], json_encode($this->getSupportedAuthenticationMethods())));

        return [
            'token_endpoint_auth_method' => $registration_parameters, 'token_endpoint_auth_method',
        ];
    }
}
