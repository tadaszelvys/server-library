<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\PasswordClient;
use OAuth2\Client\PasswordClientManager as Base;
use OAuth2\Client\PasswordClientWithDigestSupport;

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

        $digest = new PasswordClientWithDigestSupport();
        $digest->setA1Hash(hash('md5', sprintf('%s:%s:%s', 'Mufasa', 'testrealm@host.com', 'Circle Of Life')))
            ->setPlaintextSecret('Circle Of Life')
            ->setRedirectUris([])
            ->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code'])
            ->setPublicId('Mufasa');
        $this->updateClientCredentials($digest);

        $this->clients['bar'] = $bar;
        $this->clients['baz'] = $baz;
        $this->clients['Mufasa'] = $digest;
    }

    /**
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        return isset($this->clients[$client_id]) ? $this->clients[$client_id] : null;
    }
}
