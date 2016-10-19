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

use Assert\Assertion;
use OAuth2\Client\ClientInterface;
use OAuth2\Util\RequestBody;
use Psr\Http\Message\ServerRequestInterface;

abstract class ClientSecretPost implements TokenEndpointAuthMethodInterface
{
    /**
     * @var int
     */
    private $secret_lifetime;

    public function __construct($secret_lifetime = 0)
    {
        Assertion::integer($secret_lifetime);
        Assertion::greaterOrEqualThan($secret_lifetime, 0);

        $this->secret_lifetime = $secret_lifetime;
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
        $client_id = RequestBody::getParameter($request, 'client_id');
        $client_secret = RequestBody::getParameter($request, 'client_secret');

        if (!empty($client_id) && !empty($client_secret)) {
            $client_credentials = $client_secret;

            return $client_id;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkClientConfiguration(array $client_configuration, ClientInterface $client)
    {
        $client->set('client_secret', $this->createClientSecret());
        $client->set('client_secret_expires_at', (0 === $this->secret_lifetime ? 0 : time() + $this->secret_lifetime));
    }

    /**
     * {@inheritdoc}
     */
    public function isClientAuthenticated(ClientInterface $client, $client_credentials, ServerRequestInterface $request)
    {
        return hash_equals($client->get('client_secret'), $client_credentials);
    }

    /**
     * {@inheritdoc}
     */
    public function getSupportedAuthenticationMethods()
    {
        return ['client_secret_post'];
    }

    /**
     * @return string
     */
    abstract protected function createClientSecret();
}
