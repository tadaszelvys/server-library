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
 * @group TokenRevocation
 */
class PostTokenRevocationEndpointTest extends Base
{
    public function testRequestNotSecured()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'ABCD'], ['PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testRequestNotSecuredWithCallback()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'ABCD', 'callback' => 'foo.bar'], ['PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('foo.bar({"error":"invalid_request","error_description":"The request must be secured.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"})', $response->getBody()->getContents());
    }

    public function testMissingTokenParameter()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testMissingTokenParameterWithCallback()
    {
        $request = $this->createRequest('/', 'POST', ['callback' => 'foo.bar'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('foo.bar({"error":"invalid_request","error_description":"Parameter \"token\" is missing","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"})', $response->getBody()->getContents());
    }

    public function testAccessTokenNotForAuthenticatedClient()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'baz', 'PHP_AUTH_PW' => 'secret']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testAccessTokenNotForAuthenticatedClientWithCallback()
    {
        $request = $this->createRequest('/', 'POST', ['callback' => 'foo.bar'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'baz', 'PHP_AUTH_PW' => 'secret']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('foo.bar({"error":"invalid_request","error_description":"Parameter \"token\" is missing","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"})', $response->getBody()->getContents());
    }

    public function testAccessTokenRevokedForAuthenticatedConfidentialClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'ABCD'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
        $this->assertNull($this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
    }

    public function testAccessTokenRevokedForAuthenticatedConfidentialClientWithCallback()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'ABCD', 'callback' => 'foo.bar'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('foo.bar()', $response->getBody()->getContents());
        $this->assertNull($this->getJWTAccessTokenManager()->getAccessToken('ABCD'));
    }

    public function testAccessTokenRevokedForAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
        $this->assertNull($this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertNull($this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
    }

    public function testAccessTokenRevokedForAuthenticatedPublicClientWithCallback()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH', 'callback' => 'foo.bar'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('foo.bar()', $response->getBody()->getContents());
        $this->assertNull($this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertNull($this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
    }

    public function testAccessTokenNotRevokedForAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'bam']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testAccessTokenNotRevokedForAuthenticatedPublicClientWithCallback()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH', 'callback' => 'foo.bar'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'bam']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $this->assertEquals(401, $response->getStatusCode());
        $headers = $response->getHeaders();
        $this->assertTrue(array_key_exists('Cache-Control', $headers));
        $this->assertTrue(array_key_exists('Pragma', $headers));
        $this->assertTrue(array_key_exists('WWW-Authenticate', $headers));
        $this->assertEquals(1, count($headers['WWW-Authenticate']));
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testAccessTokenNotRevokedForNotAuthenticatedPublicClientAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH', 'token_type_hint' => 'refresh_token'], ['HTTPS' => 'on']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertEquals(401, $response->getStatusCode());
        $headers = $response->getHeaders();
        $this->assertTrue(array_key_exists('Cache-Control', $headers));
        $this->assertTrue(array_key_exists('Pragma', $headers));
        $this->assertTrue(array_key_exists('WWW-Authenticate', $headers));
        $this->assertEquals(1, count($headers['WWW-Authenticate']));
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testAccessTokenNotRevokedForNotAuthenticatedPublicClientWithCallbackAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'EFGH', 'callback' => 'foo.bar', 'token_type_hint' => 'refresh_token'], ['HTTPS' => 'on']);

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(AccessTokenInterface::class, $this->getJWTAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertEquals(401, $response->getStatusCode());
        $headers = $response->getHeaders();
        $this->assertTrue(array_key_exists('Cache-Control', $headers));
        $this->assertTrue(array_key_exists('Pragma', $headers));
        $this->assertTrue(array_key_exists('WWW-Authenticate', $headers));
        $this->assertEquals(1, count($headers['WWW-Authenticate']));
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testRefreshTokenRevokedForNotAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN'], ['HTTPS' => 'on']);

        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(401, $response->getStatusCode());
        $headers = $response->getHeaders();
        $this->assertTrue(array_key_exists('Cache-Control', $headers));
        $this->assertTrue(array_key_exists('Pragma', $headers));
        $this->assertTrue(array_key_exists('WWW-Authenticate', $headers));
        $this->assertEquals(1, count($headers['WWW-Authenticate']));
        $this->assertEquals('', $response->getBody()->getContents());
        $this->assertNull($this->getJWTAccessTokenManager()->getAccessToken('VALID_REFRESH_TOKEN'));
    }

    public function testRefreshRevokedForNotAuthenticatedPublicClientWithCallback()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN', 'callback' => 'foo.bar'], ['HTTPS' => 'on']);

        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(401, $response->getStatusCode());
        $headers = $response->getHeaders();
        $this->assertTrue(array_key_exists('Cache-Control', $headers));
        $this->assertTrue(array_key_exists('Pragma', $headers));
        $this->assertTrue(array_key_exists('WWW-Authenticate', $headers));
        $this->assertEquals(1, count($headers['WWW-Authenticate']));
        $this->assertEquals('', $response->getBody()->getContents());
        $this->assertNull($this->getJWTAccessTokenManager()->getAccessToken('VALID_REFRESH_TOKEN'));
    }

    public function testFooTokenNotSupported()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN', 'token_type_hint' => 'foo_token'], ['PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life', 'HTTPS' => 'on']);

        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $this->assertEquals(501, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testFooTokenNotSupportedWithCallback()
    {
        $request = $this->createRequest('/', 'POST', ['token' => 'VALID_REFRESH_TOKEN', 'callback' => 'foo.bar', 'token_type_hint' => 'foo_token'], ['PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life', 'HTTPS' => 'on']);

        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf(RefreshTokenInterface::class, $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $this->assertEquals(501, $response->getStatusCode());
        $this->assertEquals('foo.bar({"error":"unsupported_token_type","error_description":"Token type \"foo_token\" not supported","error_uri":"https:\/\/foo.test\/Error\/NotImplemented\/unsupported_token_type"})', $response->getBody()->getContents());
    }
}
