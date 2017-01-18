<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
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
     * @param ServerRequestInterface $request The request
     *
     * @throws OAuth2Exception Throw an exception if a client tried to authenticate against the server, but failed
     *
     * @return Client|null Return the client object.
     */
    public function findClient(ServerRequestInterface $request);

    /**
     * @param ServerRequestInterface           $request
     * @param Client                           $client
     * @param TokenEndpointAuthMethodInterface $authentication_method
     * @param $client_credentials
     *
     * @return bool
     */
    public function isClientAuthenticated(ServerRequestInterface $request, Client $client, TokenEndpointAuthMethodInterface $authentication_method, $client_credentials): bool;

    /**
     * @param TokenEndpointAuthMethodInterface $token_endpoint_auth_method
     *
     * @return TokenEndpointAuthMethodManagerInterface
     */
    public function addTokenEndpointAuthMethod(TokenEndpointAuthMethodInterface $token_endpoint_auth_method): self;

    /**
     * @return string[]
     */
    public function getSupportedTokenEndpointAuthMethods(): array;

    /**
     * @param string $token_endpoint_auth_method
     *
     * @return bool
     */
    public function hasTokenEndpointAuthMethod($token_endpoint_auth_method): bool;

    /**
     * @param string $token_endpoint_auth_method
     *
     * @throws \InvalidArgumentException
     *
     * @return TokenEndpointAuthMethodInterface
     */
    public function getTokenEndpointAuthMethod($token_endpoint_auth_method): TokenEndpointAuthMethodInterface;

    /**
     * @return TokenEndpointAuthMethodInterface[]
     */
    public function getTokenEndpointAuthMethods(): array;
}
