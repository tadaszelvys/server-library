<?php

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
        $this->getTokenIntrospectionEndpoint()->introspect($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Request must be secured","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testMissingTokenParameter()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspect($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Parameter \"token\" is missing","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionAllowedForAuthenticatedConfidentialClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'ABCD'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspect($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('{"active":true,"client_id":"bar","token_type":"access_token"}', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionAllowedForAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspect($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('{"active":true,"client_id":"foo","token_type":"access_token"}', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionRefusedForUnauthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'bam']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspect($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testAccessTokenIntrospectionNotForAuthenticatedPublicClientAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH', 'token_type_hint' => 'access_token'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspect($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('{"active":true,"client_id":"foo","token_type":"access_token"}', $response->getBody()->getContents());
    }

    public function testAccessTokenNotIntrospectionNotForAuthenticatedPublicClientAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH', 'token_type_hint' => 'refresh_token'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspect($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unable to find token or client not authenticated.","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testRefreshTokenIntrospectionNotForAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspect($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unable to find token or client not authenticated.","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }

    public function testFooTokenNotSupported()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN', 'token_type_hint' => 'foo_token'], ['HTTPS' => 'on']);

        $response = new Response();
        $this->getTokenIntrospectionEndpoint()->introspect($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('{"error":"invalid_request","error_description":"Unsupported token type hint","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"}', $response->getBody()->getContents());
    }
}
