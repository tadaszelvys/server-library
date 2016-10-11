<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Behaviour;

use Assert\Assertion;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface;

trait HasTokenEndpointAuthMethodManager
{
    /**
     * @var \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface|null
     */
    private $token_endpoint_auth_method_manager = null;

    /**
     * @return bool
     */
    protected function hasTokenEndpointAuthMethodManager()
    {
        return null !== $this->token_endpoint_auth_method_manager;
    }

    /**
     * @return \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface
     */
    protected function getTokenEndpointAuthMethodManager()
    {
        Assertion::true($this->hasTokenEndpointAuthMethodManager(), 'The token endpoint authentication method code manager is not available.');

        return $this->token_endpoint_auth_method_manager;
    }

    /**
     * @param \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_method_manager
     */
    protected function setTokenEndpointAuthMethodManager(TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_method_manager)
    {
        $this->token_endpoint_auth_method_manager = $token_endpoint_auth_method_manager;
    }
}
