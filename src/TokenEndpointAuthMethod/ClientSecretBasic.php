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
use Psr\Http\Message\ServerRequestInterface;

class ClientSecretBasic implements TokenEndpointAuthMethodInterface
{
    /**
     * @var string
     */
    private $realm;

    /**
     * PasswordClientManager constructor.
     *
     * @param string $realm
     */
    public function __construct($realm)
    {
        Assertion::string($realm);
        $this->realm = $realm;
    }

    /**
     * {@inheritdoc}
     */
    public function getSchemesParameters()
    {
        return [
            sprintf('Basic realm="%s",charset=UTF-8', $this->getRealm()),
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request, &$client_credentials = null)
    {
        $server_params = $request->getServerParams();
        if (array_key_exists('PHP_AUTH_USER', $server_params) && array_key_exists('PHP_AUTH_PW', $server_params)) {
            $client_credentials = $server_params['PHP_AUTH_PW'];

            return $server_params['PHP_AUTH_USER'];
        }
        $authorization_headers = $request->getHeader('Authorization');
        if (0 < count($authorization_headers)) {
            foreach ($authorization_headers as $authorization_header) {
                if (mb_strtolower(mb_substr($authorization_header, 0, 6, '8bit'), '8bit') === 'basic ') {
                    list($client_id, $client_secret) = explode(':', base64_decode(mb_substr($authorization_header, 6, mb_strlen($authorization_header, '8bit') - 6, '8bit')));
                    if (!empty($client_id) && !empty($client_secret)) {
                        $client_credentials = $client_secret;

                        return $client_id;
                    }
                }
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function checkClientConfiguration(array $client_configuration, array &$metadatas)
    {
        Assertion::keyExists('client_secret', $client_configuration, 'The parameter "client_secret" must be set.');
        Assertion::string($client_configuration['client_secret'], 'The parameter "client_secret" must be a string.');
        $metadatas['client_secret'] = $client_configuration['client_secret'];
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
        return ['client_secret_basic'];
    }

    /**
     * @return string
     */
    private function getRealm()
    {
        return $this->realm;
    }
}
