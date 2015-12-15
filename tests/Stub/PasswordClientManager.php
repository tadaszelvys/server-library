<?php

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
        $bar->setPlaintextSecret('secret');
        $bar->setRedirectUris(['http://example.com/test?good=false']);
        $bar->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'id_token', 'none', 'refresh_token', 'code', 'authorization_code']);
        $bar->setPublicId('bar');
        $this->updateClientCredentials($bar);

        $baz = new PasswordClient();
        $baz->setPlaintextSecret('secret');
        $baz->setRedirectUris([]);
        $baz->setAllowedGrantTypes(['authorization_code']);
        $baz->setPublicId('baz');
        $this->updateClientCredentials($baz);

        $digest = new PasswordClient();
        $digest->setPlaintextSecret('Circle Of Life');
        $digest->setRedirectUris([]);
        $digest->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'id_token', 'none', 'refresh_token', 'code', 'authorization_code']);
        $digest->setPublicId('Mufasa');
        $this->updateClientCredentials($digest);

        $this->clients['bar'] = $bar;
        $this->clients['baz'] = $baz;
        $this->clients['Mufasa'] = $digest;
    }
}
