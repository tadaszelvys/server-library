<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\TokenEndpointAuthMethod;

namespace OAuth2\TokenEndpointAuthMethod;

use Assert\Assertion;

final class TokenEndpointAuthMethodManager implements TokenEndpointAuthMethodManagerInterface
{
    /**
     * @var \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodInterface[]
     */
    private $token_endpoint_auth_names = [];

    /**
     * @var \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodInterface[]
     */
    private $token_endpoint_auth_methods = [];

    /**
     * {@inheritdoc}
     */
    public function addTokenEndpointAuthMethod(TokenEndpointAuthMethodInterface $token_endpoint_auth_method)
    {
        $this->token_endpoint_auth_methods[] = $token_endpoint_auth_method;
        foreach ($token_endpoint_auth_method->getSupportedAuthenticationMethods() as $method_name) {
            $this->token_endpoint_auth_names[$method_name] = $token_endpoint_auth_method;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedTokenEndpointAuthMethods()
    {
        return array_keys($this->token_endpoint_auth_names);
    }

    /**
     * {@inheritdoc}
     */
    public function hasTokenEndpointAuthMethod($token_endpoint_auth_method)
    {
        return array_key_exists($token_endpoint_auth_method, $this->token_endpoint_auth_names);
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenEndpointAuthMethod($token_endpoint_auth_method)
    {
        Assertion::true($this->hasTokenEndpointAuthMethod($token_endpoint_auth_method), sprintf('The token endpoint authentication method "%s" is not supported. Please use one of the following values: %s', $token_endpoint_auth_method, json_encode($this->getSupportedTokenEndpointAuthMethods())));

        return $this->token_endpoint_auth_names[$token_endpoint_auth_method];
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenEndpointAuthMethods()
    {
        return array_values($this->token_endpoint_auth_methods);
    }
}
