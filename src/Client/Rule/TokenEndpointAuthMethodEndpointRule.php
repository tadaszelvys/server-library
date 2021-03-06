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

use Assert\Assertion;
use OAuth2\Behaviour\HasTokenEndpointAuthMethodManager;
use OAuth2\Client\ClientInterface;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface;

class TokenEndpointAuthMethodEndpointRule implements RuleInterface
{
    use HasTokenEndpointAuthMethodManager;

    /**
     * TokenEndpointAuthMethodEndpointRule constructor.
     *
     * @param \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_method_manager
     */
    public function __construct(TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_method_manager)
    {
        $this->setTokenEndpointAuthMethodManager($token_endpoint_auth_method_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function check(ClientInterface $client, array $registration_parameters)
    {
        Assertion::keyExists($registration_parameters, 'token_endpoint_auth_method', 'The parameter "token_endpoint_auth_method" is missing.');
        Assertion::string($registration_parameters['token_endpoint_auth_method'], 'The parameter "token_endpoint_auth_method" must be a string.');
        Assertion::true($this->getTokenEndpointAuthMethodManager()->hasTokenEndpointAuthMethod($registration_parameters['token_endpoint_auth_method']), sprintf('The token endpoint authentication method "%s" is not supported. Please use one of the following values: %s', $registration_parameters['token_endpoint_auth_method'], json_encode($this->getTokenEndpointAuthMethodManager()->getSupportedTokenEndpointAuthMethods())));

        $token_endpoint_auth_method = $this->getTokenEndpointAuthMethodManager()->getTokenEndpointAuthMethod($registration_parameters['token_endpoint_auth_method']);
        $token_endpoint_auth_method->checkClientConfiguration($registration_parameters, $client);

        $client->set('token_endpoint_auth_method', $registration_parameters['token_endpoint_auth_method']);
    }

    /**
     * {@inheritdoc}
     */
    public function getPreserverParameters()
    {
        return ['client_secret_expires_at'];
    }
}
