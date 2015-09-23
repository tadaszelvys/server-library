<?php

namespace OAuth2\Test;

use Zend\Diactoros\Response;

/**
 * @group TokenRevocation
 */
class PostTokenRevocationEndpointTest extends Base
{
    public function testRequestNotSecured()
    {
        $request = $this->createRequest('/', 'POST', [], ['PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['token' => 'ABCD']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testRequestNotSecuredWithCallback()
    {
        $request = $this->createRequest('/', 'POST', [], ['PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['token' => 'ABCD', 'callback' => 'foo.bar']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('foo.bar({"error":"invalid_request","error_description":"Request must be secured","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"})', $response->getBody()->getContents());
    }

    public function testMissingTokenParameter()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query([]));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testMissingTokenParameterWithCallback()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['callback' => 'foo.bar']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('foo.bar({"error":"invalid_request","error_description":"Parameter \"token\" is missing","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"})', $response->getBody()->getContents());
    }

    public function testAccessTokenNotForAuthenticatedClient()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'baz', 'PHP_AUTH_PW' => 'secret'], [], http_build_query([]));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testAccessTokenNotForAuthenticatedClientWithCallback()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'baz', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['callback' => 'foo.bar']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals('foo.bar({"error":"invalid_request","error_description":"Parameter \"token\" is missing","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FBadRequest%2Finvalid_request"})', $response->getBody()->getContents());
    }

    public function testAccessTokenRevokedForAuthenticatedConfidentialClient()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['token' => 'ABCD']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
        $this->assertNull($this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
    }

    public function testAccessTokenRevokedForAuthenticatedConfidentialClientWithCallback()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['token' => 'ABCD', 'callback' => 'foo.bar']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('foo.bar()', $response->getBody()->getContents());
        $this->assertNull($this->getSimplestringAccessTokenManager()->getAccessToken('ABCD'));
    }

    public function testAccessTokenRevokedForAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo'], http_build_query(['token' => 'EFGH']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
        $this->assertNull($this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertNull($this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
    }

    public function testAccessTokenRevokedForAuthenticatedPublicClientWithCallback()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo'], http_build_query(['token' => 'EFGH', 'callback' => 'foo.bar']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('foo.bar()', $response->getBody()->getContents());
        $this->assertNull($this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertNull($this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
    }

    public function testAccessTokenNotRevokedForAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'bam'], http_build_query(['token' => 'EFGH']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testAccessTokenNotRevokedForAuthenticatedPublicClientWithCallback()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'bam'], http_build_query(['token' => 'EFGH', 'callback' => 'foo.bar']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('foo.bar({"error":"invalid_client","error_description":"Client authentication failed.","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FAuthenticate%2Finvalid_client"})', $response->getBody()->getContents());
    }

    public function testAccessTokenRevokedForNotAuthenticatedPublicClient()
    {
        $this->getConfiguration()->set('revoke_refresh_token_and_access_token', false);
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], [], http_build_query(['token' => 'EFGH']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
        $this->assertNull($this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $this->getConfiguration()->set('revoke_refresh_token_and_access_token', true);
    }

    public function testAccessTokenRevokedForNotAuthenticatedPublicClientWithCallback()
    {
        $this->getConfiguration()->set('revoke_refresh_token_and_access_token', false);
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], [], http_build_query(['token' => 'EFGH', 'callback' => 'foo.bar']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('foo.bar()', $response->getBody()->getContents());
        $this->assertNull($this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('REFRESH_EFGH'));
        $this->getConfiguration()->set('revoke_refresh_token_and_access_token', true);
    }

    public function testAccessTokenRevokedForNotAuthenticatedPublicClientAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], [], http_build_query(['token' => 'EFGH', 'token_type_hint' => 'access_token']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
        $this->assertNull($this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
    }

    public function testAccessTokenRevokedForNotAuthenticatedPublicClientWithCallbackAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], [], http_build_query(['token' => 'EFGH', 'callback' => 'foo.bar', 'token_type_hint' => 'access_token']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('foo.bar()', $response->getBody()->getContents());
        $this->assertNull($this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
    }

    public function testAccessTokenNotRevokedForNotAuthenticatedPublicClientAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], [], http_build_query(['token' => 'EFGH', 'token_type_hint' => 'refresh_token']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testAccessTokenNotRevokedForNotAuthenticatedPublicClientWithCallbackAndTypeHint()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], [], http_build_query(['token' => 'EFGH', 'callback' => 'foo.bar', 'token_type_hint' => 'refresh_token']));

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $this->getSimplestringAccessTokenManager()->getAccessToken('EFGH'));
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('foo.bar()', $response->getBody()->getContents());
    }

    public function testRefreshTokenRevokedForNotAuthenticatedPublicClient()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], [], http_build_query(['token' => 'VALID_REFRESH_TOKEN']));

        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
        $this->assertNull($this->getSimplestringAccessTokenManager()->getAccessToken('VALID_REFRESH_TOKEN'));
    }

    public function testRefreshRevokedForNotAuthenticatedPublicClientWithCallback()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], [], http_build_query(['token' => 'VALID_REFRESH_TOKEN', 'callback' => 'foo.bar']));

        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('foo.bar()', $response->getBody()->getContents());
        $this->assertNull($this->getSimplestringAccessTokenManager()->getAccessToken('VALID_REFRESH_TOKEN'));
    }

    public function testFooTokenNotSupported()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], [], http_build_query(['token' => 'VALID_REFRESH_TOKEN', 'token_type_hint' => 'foo_token']));

        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $this->assertEquals(501, $response->getStatusCode());
        $this->assertEquals('', $response->getBody()->getContents());
    }

    public function testFooTokenNotSupportedWithCallback()
    {
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], [], http_build_query(['token' => 'VALID_REFRESH_TOKEN', 'callback' => 'foo.bar', 'token_type_hint' => 'foo_token']));

        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $response = new Response();
        $this->getRevocationTokenEndpoint()->revoke($request, $response);
        $response->getBody()->rewind();

        $this->assertInstanceOf('\OAuth2\Token\RefreshTokenInterface', $this->getRefreshTokenManager()->getRefreshToken('VALID_REFRESH_TOKEN'));
        $this->assertEquals(501, $response->getStatusCode());
        $this->assertEquals('foo.bar({"error":"unsupported_token_type","error_description":"Token type \"foo_token\" not supported","error_uri":"https%3A%2F%2Ffoo.test%2FError%2FNotImplemented%2Funsupported_token_type"})', $response->getBody()->getContents());
    }
}
