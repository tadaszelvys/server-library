<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use Assert\Assertion;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManager as Base;

class ClientManager extends Base
{
    /**
     * @var \OAuth2\Client\Client[]
     */
    private $clients = [];

    /**
     * @var \OAuth2\Client\Client[]
     */
    private $client_ids = [];

    /**
     * ClientManager constructor.
     */
    public function __construct()
    {
        foreach ($this->getClientInformation() as $info) {
            $client = $this->createClient();
            foreach ($info['data'] as $k => $v) {
                $client->set($k, $v);
            }
            $this->clients[$info['name']] = $client;
            $this->client_ids[$client->getPublicId()] = $client;
        }
    }

    /**
     * @param string $name
     *
     * @return null|\OAuth2\Client\Client
     */
    public function getClientByName($name)
    {
        return array_key_exists($name, $this->clients) ? $this->clients[$name] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        return array_key_exists($client_id, $this->client_ids) ? $this->client_ids[$client_id] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function saveClient(ClientInterface $client)
    {
        $this->client_ids[$client->getPublicId()] = $client;
    }

    /**
     * {@inheritdoc}
     */
    public function deleteClient(ClientInterface $client)
    {
        Assertion::keyExists($this->client_ids, $client->getPublicId());
        unset($this->client_ids[$client->getPublicId()]);
    }

    /**
     * @return array
     */
    private function getKeys()
    {
        return ['keys' => [
            [
                'kid' => 'JWK1',
                'use' => 'enc',
                'kty' => 'oct',
                'k'   => 'ABEiM0RVZneImaq7zN3u_wABAgMEBQYHCAkKCwwNDg8',
            ],
            [
                'kid' => 'JWK2',
                'use' => 'sig',
                'kty' => 'oct',
                'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
            ],
        ]];
    }

    /**
     * @return array
     */
    private function getClientInformation()
    {
        return [
            [
                'name' => 'jwt1',
                'data' => [
                    'redirect_uris'                   => ['http://example.com/test?good=false'],
                    'grant_types'                     => ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
                    'response_types'                  => ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token'],
                    'token_endpoint_auth_method'      => 'private_key_jwt',
                    'id_token_encrypted_response_alg' => 'A256KW',
                    'id_token_encrypted_response_enc' => 'A256CBC-HS512',
                    'jwks'                            => $this->getKeys(),
                    'scope_policy'                    => 'error',
                    'request_uris'                    => ['https://127.0.0.1:8181/'],
                    'token_lifetime'                  => [
                        'authcode'      => 20,
                        'access_token'  => 0,
                        'refresh_token' => 2000,
                    ],
                ],
            ],
            [
                'name' => 'bar',
                'data' => [
                    'client_secret'              => 'secret',
                    'client_secret_expires_at'   => time() + 3600,
                    'redirect_uris'              => ['http://example.com/test?good=false'],
                    'grant_types'                => ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
                    'response_types'             => ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token'],
                    'token_endpoint_auth_method' => 'client_secret_jwt',
                    'scope_policy'               => 'none',
                    'token_lifetime'             => [
                        'authcode'      => 10,
                        'access_token'  => 1000,
                        'refresh_token' => 2000,
                    ],
                ],
            ],
            [
                'name' => 'baz',
                'data' => [
                    'client_secret'              => 'secret',
                    'redirect_uris'              => [],
                    'grant_types'                => ['authorization_code'],
                    'response_types'             => [],
                    'token_endpoint_auth_method' => 'client_secret_basic',
                    'scope_policy'               => 'none',
                    'token_lifetime'             => [
                        'authcode'      => 10,
                        'access_token'  => 1000,
                        'refresh_token' => 2000,
                    ],
                ],
            ],
            [
                'name' => 'resource_server',
                'data' => [
                    'client_secret'              => 'secret',
                    'redirect_uris'              => [],
                    'grant_types'                => [],
                    'response_types'             => [],
                    'token_endpoint_auth_method' => 'client_secret_basic',
                    'is_resource_server'         => true,
                    'token_lifetime'             => [
                        'authcode'      => 10,
                        'access_token'  => 1000,
                        'refresh_token' => 2000,
                    ],
                ],
            ],
            [
                'name' => 'Mufasa',
                'data' => [
                    'client_secret'              => 'Circle Of Life',
                    'redirect_uris'              => [],
                    'grant_types'                => ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
                    'response_types'             => ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token'],
                    'token_endpoint_auth_method' => 'client_secret_basic',
                    'scope_policy'               => 'none',
                    'subject_type'               => 'pairwise',
                    'token_lifetime'             => [
                        'authcode'      => 10,
                        'access_token'  => 1000,
                        'refresh_token' => 2000,
                    ],
                ],
            ],
            [
                'name' => 'Mufasa2',
                'data' => [
                    'client_secret'              => 'Circle Of Life',
                    'redirect_uris'              => [],
                    'grant_types'                => ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
                    'response_types'             => ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token'],
                    'token_endpoint_auth_method' => 'client_secret_post',
                    'scope_policy'               => 'none',
                    'token_lifetime'             => [
                        'authcode'      => 10,
                        'access_token'  => 1000,
                        'refresh_token' => 2000,
                    ],
                ],
            ],
            [
                'name' => 'mac',
                'data' => [
                    'client_secret'              => 'secret',
                    'redirect_uris'              => ['http://example.com/test?good=false'],
                    'grant_types'                => ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
                    'response_types'             => ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token'],
                    'token_types'                => ['MAC'],
                    'token_endpoint_auth_method' => 'client_secret_basic',
                    'scope_policy'               => 'none',
                    'token_lifetime'             => [
                        'authcode'      => 10,
                        'access_token'  => 1000,
                        'refresh_token' => 2000,
                    ],
                ],
            ],
            [
                'name' => 'expired',
                'data' => [
                    'client_secret'              => 'secret',
                    'client_secret_expires_at'   => time() - 3600,
                    'redirect_uris'              => ['http://example.com/test?good=false'],
                    'grant_types'                => ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
                    'response_types'             => ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token'],
                    'token_endpoint_auth_method' => 'client_secret_basic',
                    'scope_policy'               => 'none',
                    'token_lifetime'             => [
                        'authcode'      => 10,
                        'access_token'  => 1000,
                        'refresh_token' => 2000,
                    ],
                ],
            ],
            [
                'name' => 'foo',
                'data' => [
                    'grant_types'                => ['client_credentials', 'password', 'refresh_token', 'authorization_code'],
                    'response_types'             => ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token'],
                    'redirect_uris'              => ['http://example.com/test?good=false', 'http://127.0.0.1', 'https://another.uri/callback', 'urn:ietf:wg:oauth:2.0:oob', 'urn:ietf:wg:oauth:2.0:oob:auto'],
                    'token_endpoint_auth_method' => 'none',
                ],
            ],
            [
                'name' => 'foo2',
                'data' => [
                    'grant_types'                => ['client_credentials', 'password', 'refresh_token', 'authorization_code'],
                    'response_types'             => ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token'],
                    'redirect_uris'              => ['http://example.com/test?good=false', 'http://127.0.0.1', 'https://another.uri/callback', 'urn:ietf:wg:oauth:2.0:oob', 'urn:ietf:wg:oauth:2.0:oob:auto'],
                    'token_endpoint_auth_method' => 'none',
                    'sector_identifier_uri'      => 'https://www.foo.com',
                    'subject_type'               => 'pairwise',
                ],
            ],
            [
                'name' => 'fii',
                'data' => [
                    'grant_types'                => [],
                    'redirect_uris'              => ['http://example.com/test?good=false'],
                    'token_endpoint_auth_method' => 'none',
                ],
            ],
            [
                'name' => 'oof',
                'data' => [
                    'grant_types'                => [],
                    'redirect_uris'              => [],
                    'token_endpoint_auth_method' => 'none',
                ],
            ],
        ];
    }
}
