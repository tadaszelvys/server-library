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

use OAuth2\Model\Client\Client;
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
    public function __construct(string $header_name = 'X-OAuth2-Public-Client-ID')
    {
        $this->header_name = $header_name;
    }

    /**
     * {@inheritdoc}
     */
    public function getSchemesParameters(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function findClientId(ServerRequestInterface $request, &$clientCredentials = null)
    {
        $header = $request->getHeader($this->header_name);

        if (is_array($header) && 1 === count($header)) {
            return $header[0];
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkClientConfiguration(array $command_parameters, array &$validated_parameters)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function isClientAuthenticated(Client $client, $clientCredentials, ServerRequestInterface $request): bool
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedAuthenticationMethods(): array
    {
        return ['none'];
    }
}
