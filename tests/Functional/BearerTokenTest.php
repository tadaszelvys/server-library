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

/**
 * @group BearerToken
 */
class BearerTokenTest extends Base
{
    public function testAccessTokenFromQuery()
    {
        $request = $this->createRequest('/foo?access_token=ABCD');
        $access_token = $this->getAccessTokenTypeManager()->findAccessToken($request, $type);

        $this->assertEquals('ABCD', $access_token);
        $this->assertInstanceOf('\OAuth2\Token\BearerAccessToken', $type);
    }

    public function testAccessTokenFromHeader()
    {
        $request = $this->createRequest('/', 'GET', [], [], ['Authorization' => 'Bearer ABCD']);
        $access_token = $this->getAccessTokenTypeManager()->findAccessToken($request, $type);

        $this->assertEquals('ABCD', $access_token);
        $this->assertInstanceOf('\OAuth2\Token\BearerAccessToken', $type);
    }

    public function testAccessTokenFromRequestBody()
    {
        $request = $this->createRequest('/', 'POST', ['foo' => 'bar', 'access_token' => 'ABCD']);
        $access_token = $this->getAccessTokenTypeManager()->findAccessToken($request, $type);

        $this->assertEquals('ABCD', $access_token);
        $this->assertInstanceOf('\OAuth2\Token\BearerAccessToken', $type);
    }

    public function testInvalidAccessToken()
    {
        $request = $this->createRequest('/', 'GET', [], [], ['Authorization' => 'MAC ABCD']);
        $access_token = $this->getAccessTokenTypeManager()->findAccessToken($request, $type);

        $this->assertNull($access_token);
    }
}
