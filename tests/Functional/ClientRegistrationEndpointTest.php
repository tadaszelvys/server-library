<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Functional;

use OAuth2\Test\Base;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\RefreshTokenInterface;
use Zend\Diactoros\Response;

/**
 * Class ClientRegistrationEndpointTest
 *
 * @group ClientRegistrationEndpoint
 */
class ClientRegistrationEndpointTest extends Base
{
    public function testRequestNotSecured()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'ABCD'], ['PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The request must be secured.","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testBadContentTypeParameter()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Content Type must be a JSON object.","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testContentIsNotAValidJsonObject()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], ['Content-Type' => 'application/json'], 'hello world!');

        $response = new Response();
        $this->getClientRegistrationEndpoint()->register($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertRegExp('{"error":"invalid_request","error_description":"Body contains an invalid JSON object.","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }
}
