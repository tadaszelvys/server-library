<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\PublicClient;
use OAuth2\Client\PublicClientManager as Base;
use Psr\Http\Message\ServerRequestInterface;

class PublicClientManager extends Base
{
    /**
     * @var \OAuth2\Client\PublicClient[]
     */
    private $clients = [];

    public function __construct()
    {
        $foo = new PublicClient();
        $foo->setPublicId('foo')
            ->setAllowedGrantTypes(['client_credentials', 'password', 'token', 'id_token', 'none', 'refresh_token', 'code', 'authorization_code'])
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
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param string|null                              $client_public_id_found
     *
     * @return string|null
     */
    protected function findClientUsingHeader(ServerRequestInterface $request, &$client_public_id_found = null)
    {
        $header = $request->getHeader('X-OAuth2-Public-Client-ID');

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
