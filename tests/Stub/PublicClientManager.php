<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\PublicClientManager as Base;
use Symfony\Component\HttpFoundation\Request;

class PublicClientManager extends Base
{
    /**
     * @var \OAuth2\Test\Stub\PublicClient[]
     */
    private $clients = [];

    public function __construct()
    {
        $foo = new PublicClient();
        $foo->setPublicId('foo')
            ->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code'])
            ->setRedirectUris(['http://example.com/test?good=false', 'https://another.uri/callback']);

        $oof = new PublicClient();
        $oof->setPublicId('oof')
            ->setAllowedGrantTypes([])
            ->setRedirectUris([]);

        $fii = new PublicClient();
        $fii->setPublicId('fii')
            ->setAllowedGrantTypes([])
            ->setRedirectUris(['http://example.com/test?good=false']);
        $this->clients['foo'] = $foo;
        $this->clients['oof'] = $oof;
        $this->clients['fii'] = $fii;
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
    protected function findClientMethods()
    {
        return [
            'findClientUsingHeader',
        ];
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param string|null                               $client_public_id_found
     *
     * @return string|null
     */
    protected function findClientUsingHeader(Request $request, &$client_public_id_found = null)
    {
        $header = $request->headers->get('X-OAuth2-Public-Client-ID');

        if (empty($header)) {
            return;
        } elseif (is_array($header)) {
            $client_public_id_found = $header[0];

            return $header[0];
        } else {
            $client_public_id_found = $header;

            return $header;
        }
    }
}
