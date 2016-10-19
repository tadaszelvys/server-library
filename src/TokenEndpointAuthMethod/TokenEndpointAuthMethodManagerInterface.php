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

use Psr\Http\Message\ServerRequestInterface;

interface TokenEndpointAuthMethodManagerInterface
{
    /**
     * Find a client ID using the request
     * This interface should send the request to all its ClientManager and return null or a ClientInterface object.
     * If client is Confidential, the client credentials must be checked by by the client manager.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     *
     * @throws \OAuth2\Exception\BaseExceptionInterface Throw an exception if a client tried to authenticate against the server, but failed
     *
     * @return \OAuth2\Client\ClientInterface Return the client object.
     */
    public function findClient(ServerRequestInterface $request);

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return \OAuth2\Exception\BaseExceptionInterface
     */
    public function buildAuthenticationException(ServerRequestInterface $request);

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
