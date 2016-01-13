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
use Zend\Diactoros\Response;

/**
 * @group TokenIntrospection
 */
class TokenIntrospectionEndpointTest extends Base
{
    public function testRequestNotSecured()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'ABCD'], ['PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Request must be secured","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testMissingTokenParameter()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Parameter \"token\" is missing","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionAllowedForAuthenticatedConfidentialClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'ABCD'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertRegExp('{"active":true,"client_id":"bar","token_type":"Bearer","exp":[0-9]+,"sub":"bar"}', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionAllowedForAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertRegExp('{"active":true,"client_id":"foo","token_type":"Bearer","exp":[0-9]+,"sub":"foo"}', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionAllowedForResourceServer()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH'], ['HTTPS' => 'on'], ['X-OAuth2-Resource-Server' => 'SERVER1']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertRegExp('{"active":true,"client_id":"foo","token_type":"Bearer","exp":[0-9]+,"sub":"foo"}', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionNotAllowedForResourceServerFromDisallowedIpAddress()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH'], ['HTTPS' => 'on', 'REMOTE_ADDR' => '192.168.1.12'], ['X-OAuth2-Resource-Server' => 'SERVER1']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unable to find token or client not authenticated.","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionAllowedForResourceServerFromTrustedProxy()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH'], ['HTTPS' => 'on', 'REMOTE_ADDR' => '127.0.0.1'], ['X-OAuth2-Resource-Server' => 'SERVER2', 'X_FORWARDED_FOR' => '192.168.1.12']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertRegExp('{"active":true,"client_id":"foo","token_type":"Bearer","exp":[0-9]+,"sub":"foo"}', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionRefusedForUnauthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'bam']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionNotForAuthenticatedPublicClientAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH', 'token_type_hint' => 'Bearer'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unsupported token type hint","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testAccessTokenNotIntrospectionNotForAuthenticatedPublicClientAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH', 'token_type_hint' => 'refresh_token'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unable to find token or client not authenticated.","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testRefreshTokenIntrospectionNotForAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unable to find token or client not authenticated.","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testRefreshTokenIntrospection()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertRegExp('{"active":true,"client_id":"bar","exp":[0-9]+,"sub":"bar","scope":\["scope1","scope2","scope3"\]}', $response->getBody()->getContents());
    }

    public function testTokenNotFound()
    {
        $request = $this->createRequest('/', 'POST', ['token' => '__BAD_TOKEN__'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertRegExp('{"error":"invalid_request","error_description":"Unable to find token or client not authenticated.","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testFooTokenNotSupported()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN', 'token_type_hint' => 'foo_token'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unsupported token type hint","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }
}
