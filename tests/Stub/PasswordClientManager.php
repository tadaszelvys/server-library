<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\PasswordClientInterface;
use OAuth2\Client\PasswordClientManager as Base;

class PasswordClientManager extends Base
{
    private $clients = array();

    public function __construct()
    {
        $bar = new PasswordClient();
        $bar->setPublicId('bar')
            ->setSecret('secret')
            ->setAllowedGrantTypes(array('client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code'))
            ->setRedirectUris(array('http://example.com/test?good=false'))
        ;

        $baz = new PasswordClient();
        $baz->setPublicId('baz')
            ->setSecret('secret')
            ->setAllowedGrantTypes(array('authorization_code'))
            ->setRedirectUris(array())
        ;
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

    /**
     * {@inheritdoc}
     */
    protected function checkClientCredentials(PasswordClientInterface $client, $secret)
    {
        if (!$client instanceof PasswordClient) {
            return false;
        }

        return $client->getSecret() === $secret;
    }
}
