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

use OAuth2\Client\ClientInterface;
use Psr\Http\Message\ServerRequestInterface;

class None implements TokenEndpointAuthMethodInterface
{
    /**
     * @var string
     */
    private $header_name;

    /**
     * None constructor.
     *
     * @param string $header_name
     */
    public function __construct($header_name = 'X-OAuth2-Public-Client-ID')
    {
        $this->header_name = $header_name;
    }

    /**
     * {@inheritdoc}
     */
    public function getSchemesParameters()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request, &$client_credentials = null)
    {
        $header = $request->getHeader($this->header_name);

        if (is_array($header) && 1 === count($header)) {
            return $header[0];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkClientConfiguration(array $client_configuration, ClientInterface $client)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function isClientAuthenticated(ClientInterface $client, $client_credentials, ServerRequestInterface $request)
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedAuthenticationMethods()
    {
        return ['none'];
    }
}
