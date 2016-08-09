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

final class TokenEndpointAuthMethodManager implements TokenEndpointAuthMethodManagerInterface
{
    /**
     * @var \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodInterface[]
     */
    private $token_endpoint_auth_methods = [];

    /**
     * {@inheritdoc}
     */
    public function addTokenEndpointAuthMethodManager(TokenEndpointAuthMethodInterface $token_endpoint_auth_method)
    {
        $this->token_endpoint_auth_methods[] = $token_endpoint_auth_method;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedTokenEndpointAuthMethods()
    {
        $result = [];
        foreach ($this->token_endpoint_auth_methods as $method) {
            $result = array_merge(
                $result,
                $method->getSupportedAuthenticationMethods()
            );
        }

        return array_unique($result);
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenEndpointAuthMethods()
    {
        return $this->token_endpoint_auth_methods;
    }


}
