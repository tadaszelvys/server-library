<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\PasswordClient;
use OAuth2\Client\PasswordClientManager as Base;

class PasswordClientManager extends Base
{
    /**
     * @var \OAuth2\Client\PasswordClient[]
     */
    private $clients = [];

    public function __construct()
    {
        $bar = new PasswordClient();
        $bar->setPlaintextSecret('secret')
            ->setRedirectUris(['http://example.com/test?good=false'])
            ->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code'])
            ->setPublicId('bar');
        $this->updateClientCredentials($bar);

        $baz = new PasswordClient();
        $baz->setPlaintextSecret('secret')
            ->setRedirectUris([])
            ->setAllowedGrantTypes(['authorization_code'])
            ->setPublicId('baz');
        $this->updateClientCredentials($baz);

        $this->clients['bar'] = $bar;
        $this->clients['baz'] = $baz;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        return isset($this->clients[$client_id]) ? $this->clients[$client_id] : null;
    }
}
