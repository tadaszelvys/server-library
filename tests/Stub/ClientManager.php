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

use Base64Url\Base64Url;
use OAuth2\Client\ClientManager as Base;
use OAuth2\Exception\ExceptionManagerInterface;

class ClientManager extends Base
{
    /**
     * @var \OAuth2\Client\Client[]
     */
    private $clients = [];

    /**
     * JWTClientManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface $exception_manager
     */
    public function __construct(ExceptionManagerInterface $exception_manager)
    {
        parent::__construct(
            $exception_manager
        );

        $keys = ['keys' => [[
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

        $jwt1 = $this->createClient();
        $jwt1->setRedirectUris(['http://example.com/test?good=false']);
        $jwt1->setGrantTypes(['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $jwt1->setResponseTypes(['token', 'id_token', 'none', 'code']);
        $jwt1->setPublicId('jwt1');
        $jwt1->setTokenEndpointAuthMethod('private_key_jwt');
        $jwt1->set('id_token_encrypted_response_alg', 'A256KW');
        $jwt1->set('id_token_encrypted_response_enc', 'A256CBC-HS512');
        $jwt1->set('jwks', $keys);
        $jwt1->set('scope_policy', 'error');

        $jwt2 = $this->createClient();
        $jwt2->setRedirectUris([]);
        $jwt2->setGrantTypes(['authorization_code']);
        $jwt2->setTokenEndpointAuthMethod('private_key_jwt');
        $jwt2->setPublicId('jwt2');

        $bar = $this->createClient();
        $bar->set('client_secret', 'secret');
        $bar->set('client_secret_expires_at', time() + 3600);
        $bar->setRedirectUris(['http://example.com/test?good=false']);
        $bar->setGrantTypes(['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $bar->setResponseTypes(['token', 'id_token', 'none', 'code']);
        $bar->setPublicId('bar');
        $bar->setTokenEndpointAuthMethod('client_secret_jwt');
        $bar->set('scope_policy', 'none');

        $baz = $this->createClient();
        $baz->set('client_secret', 'secret');
        $baz->setRedirectUris([]);
        $baz->setGrantTypes(['authorization_code']);
        $baz->setResponseTypes([]);
        $baz->setPublicId('baz');
        $baz->setTokenEndpointAuthMethod('client_secret_basic');
        $baz->set('scope_policy', 'none');

        $resource_server = $this->createClient();
        $resource_server->set('client_secret', 'secret');
        $resource_server->setRedirectUris([]);
        $resource_server->setGrantTypes([]);
        $resource_server->setResponseTypes([]);
        $resource_server->setPublicId('resource_server');
        $resource_server->setTokenEndpointAuthMethod('client_secret_basic');
        $resource_server->set('is_resource_server', true);

        $mufasa = $this->createClient();
        $mufasa->set('client_secret', 'Circle Of Life');
        $mufasa->setRedirectUris([]);
        $mufasa->setGrantTypes(['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $mufasa->setResponseTypes(['token', 'id_token', 'none', 'code']);
        $mufasa->setPublicId('Mufasa');
        $mufasa->setTokenEndpointAuthMethod('client_secret_basic');
        $mufasa->set('scope_policy', 'none');
        $mufasa->set('subject_type', 'pairwise');

        $mufasa2 = $this->createClient();
        $mufasa2->set('client_secret', 'Circle Of Life');
        $mufasa2->setRedirectUris([]);
        $mufasa2->setGrantTypes(['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $mufasa2->setResponseTypes(['token', 'id_token', 'none', 'code']);
        $mufasa2->setPublicId('Mufasa2');
        $mufasa2->setTokenEndpointAuthMethod('client_secret_post');
        $mufasa2->set('scope_policy', 'none');

        $mac = $this->createClient();
        $mac->set('client_secret', 'secret');
        $mac->setRedirectUris(['http://example.com/test?good=false']);
        $mac->setGrantTypes(['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $mac->setResponseTypes(['token', 'id_token', 'none', 'code']);
        $mac->setPublicId('mac');
        $mac->set('token_types', ['MAC']);
        $mac->setTokenEndpointAuthMethod('client_secret_basic');
        $mac->set('scope_policy', 'none');

        $expired = $this->createClient();
        $expired->set('client_secret', 'secret');
        $expired->set('client_secret_expires_at', time() - 3600);
        $expired->setRedirectUris(['http://example.com/test?good=false']);
        $expired->setGrantTypes(['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $expired->setResponseTypes(['token', 'id_token', 'none', 'code']);
        $expired->setPublicId('expired');
        $expired->setTokenEndpointAuthMethod('client_secret_basic');
        $expired->set('scope_policy', 'none');

        $foo = $this->createClient();
        $foo->setPublicId('foo');
        $foo->setGrantTypes(['client_credentials', 'password', 'refresh_token', 'authorization_code']);
        $foo->setResponseTypes(['token', 'id_token', 'none', 'code']);
        $foo->setRedirectUris(['http://example.com/test?good=false', 'http://127.0.0.1', 'https://another.uri/callback', 'urn:ietf:wg:oauth:2.0:oob', 'urn:ietf:wg:oauth:2.0:oob:auto']);
        $foo->setTokenEndpointAuthMethod('none');

        $oof = $this->createClient();
        $oof->setPublicId('oof');
        $oof->setGrantTypes([]);
        $oof->setRedirectUris([]);
        $oof->setTokenEndpointAuthMethod('none');

        $fii = $this->createClient();
        $fii->setPublicId('fii');
        $fii->setGrantTypes([]);
        $fii->setRedirectUris(['http://example.com/test?good=false']);
        $fii->setTokenEndpointAuthMethod('none');

        $this->clients['foo'] = $foo;
        $this->clients['oof'] = $oof;
        $this->clients['fii'] = $fii;

        $this->clients['jwt1'] = $jwt1;
        $this->clients['jwt2'] = $jwt2;

        $this->clients['bar'] = $bar;
        $this->clients['baz'] = $baz;
        $this->clients['Mufasa'] = $mufasa;
        $this->clients['Mufasa2'] = $mufasa2;
        $this->clients['mac'] = $mac;
        $this->clients['expired'] = $expired;
        $this->clients['resource_server'] = $resource_server;
    }

    public function createClient()
    {
        $client = new Client();
        $client->setPublicId(Base64Url::encode(random_bytes(50)));
        $client->setGrantTypes(['authorization_code']);
        $client->setResponseTypes(['code']);
        $client->setTokenEndpointAuthMethod('client_basic_secret');
        $client->set('secret', Base64Url::encode(random_bytes(30)));

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        return isset($this->clients[$client_id]) ? $this->clients[$client_id] : null;
    }
}
