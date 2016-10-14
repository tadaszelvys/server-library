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
 * @group TokenIntrospection
 */
class TokenIntrospectionEndpointTest extends Base
{
    public function testRequestNotSecured()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'ABCD'], ['PHP_AUTH_USER' => $this->getClientManager()->getClientByName('Mufasa')->getPublicId(), 'PHP_AUTH_PW' => 'Circle Of Life']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"The request must be secured.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testMissingTokenParameter()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('Mufasa')->getPublicId(), 'PHP_AUTH_PW' => 'Circle Of Life']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Parameter \"token\" is missing","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionAllowedForAuthenticatedConfidentialClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'ABCD'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('Mufasa')->getPublicId(), 'PHP_AUTH_PW' => 'Circle Of Life']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertRegExp('{"active":true,"client_id":"[^"]+","token_type":"Bearer","exp":[0-9]+}', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionAllowedForResourceServer()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'ABCD'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('resource_server')->getPublicId(), 'PHP_AUTH_PW' => 'secret']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertRegExp('{"active":true,"client_id":"[^"]+","token_type":"Bearer","exp":[0-9]+,"sub":"[^"]+","metadatas":\["plic","ploc","pluc"\],"parameters":{"foo":"bar"}}', $content);
    }

    public function testAccessTokenIntrospectionAllowedForAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => $this->getClientManager()->getClientByName('foo')->getPublicId()]);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertRegExp('{"active":true,"client_id":"[^"]+","token_type":"Bearer","exp":[0-9]+,"sub":"[^"]+"}', $response->getBody()->getContents());
    }

    public function testAuthCodeIntrospectionAllowedForAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_AUTH_CODE_TO_BE_REVOKED'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => $this->getClientManager()->getClientByName('foo')->getPublicId()]);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertRegExp('/{"active"\:true,"client_id"\:"[^"]+","exp"\:[0-9]+,"scp"\:\["scope1","scope2"\]}/', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionRefusedForUnauthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'bam']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(401, $response->getStatusCode());
        $headers = $response->getHeaders();
        $this->assertTrue(array_key_exists('Cache-Control', $headers));
        $this->assertTrue(array_key_exists('Pragma', $headers));
        $this->assertTrue(array_key_exists('WWW-Authenticate', $headers));
        $this->assertEquals(1, count($headers['WWW-Authenticate']));
    }

    public function testAccessTokenIntrospectionNotForAuthenticatedPublicClientAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH', 'token_type_hint' => 'Bearer'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => $this->getClientManager()->getClientByName('foo')->getPublicId()]);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unsupported token type hint","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testAccessTokenNotIntrospectionNotForAuthenticatedPublicClientAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH', 'token_type_hint' => 'refresh_token'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('Mufasa')->getPublicId(), 'PHP_AUTH_PW' => 'Circle Of Life']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unable to find token or client not authenticated.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testRefreshTokenIntrospectionNotForAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(401, $response->getStatusCode());
        $headers = $response->getHeaders();
        $this->assertTrue(array_key_exists('Cache-Control', $headers));
        $this->assertTrue(array_key_exists('Pragma', $headers));
        $this->assertTrue(array_key_exists('WWW-Authenticate', $headers));
        $this->assertEquals(1, count($headers['WWW-Authenticate']));
    }

    public function testRefreshTokenIntrospection()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('Mufasa')->getPublicId(), 'PHP_AUTH_PW' => 'Circle Of Life']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertRegExp('{"active":true,"client_id":"[^"]+","exp":[0-9]+,"scp":\["scope1","scope2","scope3"\]}', $response->getBody()->getContents());
    }

    public function testTokenNotFound()
    {
        $request = $this->createRequest('/', 'POST', ['token' => '__BAD_TOKEN__'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('Mufasa')->getPublicId(), 'PHP_AUTH_PW' => 'Circle Of Life']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unable to find token or client not authenticated.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testFooTokenNotSupported()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN', 'token_type_hint' => 'foo_token'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => $this->getClientManager()->getClientByName('Mufasa')->getPublicId(), 'PHP_AUTH_PW' => 'Circle Of Life']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspection($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unsupported token type hint","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }
}
