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

use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface;

trait HasTokenEndpointAuthMethodManager
{
    /**
     * @var \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface
     */
    private $token_endpoint_auth_method_manager;

    /**
     * @return \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface
     */
    protected function getTokenEndpointAuthMethodManager()
    {
        return $this->token_endpoint_auth_method_manager;
    }

    /**
     * @param \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_method_manager
     */
    private function setTokenEndpointAuthMethodManager(TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_method_manager)
    {
        $this->token_endpoint_auth_method_manager = $token_endpoint_auth_method_manager;
    }
}
