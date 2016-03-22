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

use OAuth2\Client\PasswordClientManager as Base;

class PasswordClientManager extends Base
{
    /**
     * @var \OAuth2\Client\PasswordClient[]
     */
    private $clients = [];

    /**
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        return isset($this->clients[$client_id]) ? $this->clients[$client_id] : null;
    }

    public function createClients()
    {
        $bar = new PasswordClient();
        $bar->setSecret('secret');
        $bar->setRedirectUris(['http://example.com/test?good=false']);
        $bar->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'id_token', 'none', 'refresh_token', 'code', 'authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer']);
        $bar->setPublicId('bar');
        $bar->setAllowedSignatureAlgorithms(['HS256', 'HS512']);

        $baz = new PasswordClient();
        $baz->setSecret('secret');
        $baz->setRedirectUris([]);
        $baz->setAllowedGrantTypes(['authorization_code']);
        $baz->setPublicId('baz');

        $digest = new PasswordClient();
        $digest->setSecret('Circle Of Life');
        $digest->setRedirectUris([]);
        $digest->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'id_token', 'none', 'refresh_token', 'code', 'authorization_code']);
        $digest->setPublicId('Mufasa');

        $mac = new PasswordClient();
        $mac->setSecret('secret');
        $mac->setRedirectUris(['http://example.com/test?good=false']);
        $mac->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'id_token', 'none', 'refresh_token', 'code', 'authorization_code']);
        $mac->setPublicId('mac');

        $this->clients['bar'] = $bar;
        $this->clients['baz'] = $baz;
        $this->clients['Mufasa'] = $digest;
        $this->clients['mac'] = $mac;
    }
}
