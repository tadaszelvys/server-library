<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Functional;

use OAuth2\Test\Base;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

/**
 * @group OpenIDConnect
 */
class OpenIDConnectTest extends Base
{
    public function testCodeTokenSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'code token',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getEndUserManager()->getEndUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&access_token=[^"]+&token_type=Bearer&expires_in=3600&scope=scope1\+scope2$/', $response->getHeader('Location')[0]);
    }

    public function testCodeIdTokenTokenSuccess()
    {
        $this->markTestIncomplete('ID Token not yet implemented');

        return;

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'code id_token token',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getEndUserManager()->getEndUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&id_token=[^"]+&access_token=[^"]+&token_type=Bearer&expires_in=3600&scope=scope1\+scope2$/', $response->getHeader('Location')[0]);
    }

    public function testNoneSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'none',
            'state'         => '0123456789',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getEndUserManager()->getEndUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);

        $this->assertEquals('http://example.com/test?good=false&state=0123456789', $response->getHeader('Location')[0]);
    }
}
