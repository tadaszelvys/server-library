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
use OAuth2\Model\Client\ClientId;
use Psr\Http\Message\ServerRequestInterface;

class None implements TokenEndpointAuthMethodInterface
{
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
        $parameters = $request->getParsedBody() ?? [];
        if (array_key_exists('client_id', $parameters) && !array_key_exists('client_secret', $parameters)) {
            return ClientId::create($parameters['client_id']);
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
