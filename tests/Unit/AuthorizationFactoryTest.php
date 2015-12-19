<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Unit;

use OAuth2\Test\Base;

/**
 * @group AuthorizationFactory
 */
class AuthorizationFactoryTest extends Base
{
    public function testCreateValidAuthorization()
    {
        $params = [
            'client_id'     => 'foo',
            'state'         => '0123456789',
            'scope'         => 'scope1 scope2',
            'response_type' => 'token',
            'display'       => 'page',
            'prompt'        => 'none',
        ];
        $request = $this->createRequest('/?'.http_build_query($params));
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getEndUserManager()->getEndUser('user1'),
        true
        );

        $this->assertEquals('0123456789', $authorization->get('state'));
        $this->assertEquals('foo', $authorization->get('client_id'));
        $this->assertEquals('foo', $authorization->getClient()->getPublicId());
        $this->assertEquals('token', $authorization->get('response_type'));
        $this->assertEquals('page', $authorization->get('display'));
        $this->assertEquals('none', $authorization->get('prompt'));
        $this->assertEquals('scope1 scope2', $authorization->get('scope'));
        $this->assertEquals($params, $authorization->getQueryParams());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage  Invalid "prompt" parameter. Allowed values are [null,"none","login","consent","select_account"]
     */
    public function testCreateAuthorizationWithBadPrompt()
    {
        $params = [
            'client_id'     => 'foo',
            'state'         => '0123456789',
            'scope'         => 'scope1 scope2',
            'response_type' => 'token',
            'display'       => 'page',
            'prompt'        => 'foo',
        ];
        $request = $this->createRequest('/?'.http_build_query($params));
        $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getEndUserManager()->getEndUser('user1'),
            true
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage  Invalid "display" parameter. Allowed values are [null,"page","popup","touch","wap"]
     */
    public function testCreateAuthorizationWithBadDisplay()
    {
        $params = [
            'client_id'     => 'foo',
            'state'         => '0123456789',
            'scope'         => 'scope1 scope2',
            'response_type' => 'token',
            'display'       => 'foo',
            'prompt'        => 'none',
        ];
        $request = $this->createRequest('/?'.http_build_query($params));
        $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getEndUserManager()->getEndUser('user1'),
            true
        );
    }
}
