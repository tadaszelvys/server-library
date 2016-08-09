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
use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManager as Base;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface;

class ClientManager extends Base
{
    /**
     * @var \OAuth2\Client\Client[]
     */
    private $clients = [];

    /**
     * ClientManager constructor.
     *
     * @param \OAuth2\TokenEndpointAuthMethod\TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_method_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                             $exception_manager
     */
    public function __construct(TokenEndpointAuthMethodManagerInterface $token_endpoint_auth_method_manager, ExceptionManagerInterface $exception_manager)
    {
        parent::__construct(
            $token_endpoint_auth_method_manager,
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
        $jwt1->set('redirect_uris', ['http://example.com/test?good=false']);
        $jwt1->set('grant_types', ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $jwt1->set('response_types', ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token']);
        $jwt1->setPublicId('jwt1');
        $jwt1->set('token_endpoint_auth_method', 'private_key_jwt');
        $jwt1->set('id_token_encrypted_response_alg', 'A256KW');
        $jwt1->set('id_token_encrypted_response_enc', 'A256CBC-HS512');
        $jwt1->set('jwks', $keys);
        $jwt1->set('scope_policy', 'error');
        $jwt1->set('request_uris', ['https://gist.githubusercontent.com/Spomky/']);

        $jwt2 = $this->createClient();
        $jwt2->set('redirect_uris', []);
        $jwt2->set('grant_types', ['authorization_code']);
        $jwt2->set('token_endpoint_auth_method', 'private_key_jwt');
        $jwt2->setPublicId('jwt2');

        $bar = $this->createClient();
        $bar->set('client_secret', 'secret');
        $bar->set('client_secret_expires_at', time() + 3600);
        $bar->set('redirect_uris', ['http://example.com/test?good=false']);
        $bar->set('grant_types', ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $bar->set('response_types', ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token']);
        $bar->setPublicId('bar');
        $bar->set('token_endpoint_auth_method', 'client_secret_jwt');
        $bar->set('scope_policy', 'none');

        $baz = $this->createClient();
        $baz->set('client_secret', 'secret');
        $baz->set('redirect_uris', []);
        $baz->set('grant_types', ['authorization_code']);
        $baz->set('response_types', []);
        $baz->setPublicId('baz');
        $baz->set('token_endpoint_auth_method', 'client_secret_basic');
        $baz->set('scope_policy', 'none');

        $resource_server = $this->createClient();
        $resource_server->set('client_secret', 'secret');
        $resource_server->set('redirect_uris', []);
        $resource_server->set('grant_types', []);
        $resource_server->set('response_types', []);
        $resource_server->setPublicId('resource_server');
        $resource_server->set('token_endpoint_auth_method', 'client_secret_basic');
        $resource_server->set('is_resource_server', true);

        $mufasa = $this->createClient();
        $mufasa->set('client_secret', 'Circle Of Life');
        $mufasa->set('redirect_uris', []);
        $mufasa->set('grant_types', ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $mufasa->set('response_types', ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token']);
        $mufasa->setPublicId('Mufasa');
        $mufasa->set('token_endpoint_auth_method', 'client_secret_basic');
        $mufasa->set('scope_policy', 'none');
        $mufasa->set('subject_type', 'pairwise');

        $mufasa2 = $this->createClient();
        $mufasa2->set('client_secret', 'Circle Of Life');
        $mufasa2->set('redirect_uris', []);
        $mufasa2->set('grant_types', ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $mufasa2->set('response_types', ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token']);
        $mufasa2->setPublicId('Mufasa2');
        $mufasa2->set('token_endpoint_auth_method', 'client_secret_post');
        $mufasa2->set('scope_policy', 'none');

        $mac = $this->createClient();
        $mac->set('client_secret', 'secret');
        $mac->set('redirect_uris', ['http://example.com/test?good=false']);
        $mac->set('grant_types', ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $mac->set('response_types', ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token']);
        $mac->setPublicId('mac');
        $mac->set('token_types', ['MAC']);
        $mac->set('token_endpoint_auth_method', 'client_secret_basic');
        $mac->set('scope_policy', 'none');

        $expired = $this->createClient();
        $expired->set('client_secret', 'secret');
        $expired->set('client_secret_expires_at', time() - 3600);
        $expired->set('redirect_uris', ['http://example.com/test?good=false']);
        $expired->set('grant_types', ['client_credentials', 'password', 'refresh_token', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $expired->set('response_types', ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token']);
        $expired->setPublicId('expired');
        $expired->set('token_endpoint_auth_method', 'client_secret_basic');
        $expired->set('scope_policy', 'none');

        $foo = $this->createClient();
        $foo->setPublicId('foo');
        $foo->set('grant_types', ['client_credentials', 'password', 'refresh_token', 'authorization_code']);
        $foo->set('response_types', ['token', 'id_token', 'none', 'code', 'code id_token', 'id_token token', 'code token', 'code id_token token']);
        $foo->set('redirect_uris', ['http://example.com/test?good=false', 'http://127.0.0.1', 'https://another.uri/callback', 'urn:ietf:wg:oauth:2.0:oob', 'urn:ietf:wg:oauth:2.0:oob:auto']);
        $foo->set('token_endpoint_auth_method', 'none');

        $oof = $this->createClient();
        $oof->setPublicId('oof');
        $oof->set('grant_types', []);
        $oof->set('redirect_uris', []);
        $oof->set('token_endpoint_auth_method', 'none');

        $fii = $this->createClient();
        $fii->setPublicId('fii');
        $fii->set('grant_types', []);
        $fii->set('redirect_uris', ['http://example.com/test?good=false']);
        $fii->set('token_endpoint_auth_method', 'none');

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
        $client->set('grant_types', ['authorization_code']);
        $client->set('response_types', ['code']);
        $client->set('token_endpoint_auth_method', 'client_basic_secret');
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

    /**
     * {@inheritdoc}
     */
    public function saveClient(ClientInterface $client)
    {
        $this->clients[$client->getPublicId()] = $client;
    }
}
