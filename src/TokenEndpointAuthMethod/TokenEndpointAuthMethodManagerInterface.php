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

interface TokenEndpointAuthMethodManagerInterface
{
    /**
     * @param \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodInterface $token_endpoint_auth_method
     */
    public function addTokenEndpointAuthMethod(TokenEndpointAuthMethodInterface $token_endpoint_auth_method);

    /**
     * @return string[]
     */
    public function getSupportedTokenEndpointAuthMethods();

    /**
     * @param string $token_endpoint_auth_method
     *
     * @return bool
     */
    public function hasTokenEndpointAuthMethod($token_endpoint_auth_method);

    /**
     * @param string $token_endpoint_auth_method
     *
     * @throws \InvalidArgumentException
     *
     * @return \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodInterface
     */
    public function getTokenEndpointAuthMethod($token_endpoint_auth_method);

    /**
     * @return \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodInterface[]
     */
    public function getTokenEndpointAuthMethods();
}
