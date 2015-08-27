<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\PublicClientManager as Base;
use Symfony\Component\HttpFoundation\Request;

class PublicClientManager extends Base
{
    /**
     * @var \OAuth2\Test\Stub\PublicClient[]
     */
    private $clients = array();

    public function __construct()
    {
        $foo = new PublicClient();
        $foo->setPublicId('foo')
            ->setAllowedGrantTypes(array('client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code'))
            ->setRedirectUris(array('http://example.com/test?good=false', 'https://another.uri/callback'))
            ;

        $oof = new PublicClient();
        $oof->setPublicId('oof')
            ->setAllowedGrantTypes(array())
            ->setRedirectUris(array())
            ;

        $fii = new PublicClient();
        $fii->setPublicId('fii')
            ->setAllowedGrantTypes(array())
            ->setRedirectUris(array('http://example.com/test?good=false'))
            ;
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
        return array(
            'findClientUsingHeader',
        );
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return null|string
     */
    protected function findClientUsingHeader(Request $request)
    {
        $header = $request->headers->get('X-OAuth2-Public-Client-ID');

        if (empty($header)) {
            return;
        } elseif (is_array($header)) {
            return $header[0];
        } else {
            return $header;
        }
    }
}
