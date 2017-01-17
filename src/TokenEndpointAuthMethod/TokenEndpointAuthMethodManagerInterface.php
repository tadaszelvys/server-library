<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\TokenEndpointAuthMethod;

use OAuth2\Model\Client\Client;
use OAuth2\Response\OAuth2Exception;
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
     * @throws OAuth2Exception Throw an exception if a client tried to authenticate against the server, but failed
     *
     * @return Client Return the client object.
     */
    public function findClient(ServerRequestInterface $request);

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     *
     * @return OAuth2Exception
     */
    public function buildAuthenticationException(ServerRequestInterface $request);

    /**
     * @param TokenEndpointAuthMethodInterface $token_endpoint_auth_method
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
     * @return TokenEndpointAuthMethodInterface
     */
    public function getTokenEndpointAuthMethod($token_endpoint_auth_method);

    /**
     * @return TokenEndpointAuthMethodInterface[]
     */
    public function getTokenEndpointAuthMethods();
}
