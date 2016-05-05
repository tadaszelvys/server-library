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

use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Test\Base;
use Zend\Diactoros\Response;

/**
 * @group RefreshTokenGrantType
 */
class RefreshTokenGrantTypeTest extends Base
{
    public function testUnsecuredRequest()
    {
        $response = new Response();
        $request = $this->createRequest();

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The request must be secured.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testNotPostMethod()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'GET', [], ['HTTPS' => 'on']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Method must be POST.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeIsMissing()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $this->assertEquals('Invalid or unsupported request.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testUnknownClient()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'refresh_token'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'plic', 'PHP_AUTH_PW' => 'secret']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('Client authentication failed.', $e->getDescription());
            $this->assertEquals(401, $e->getHttpCode());
        }
    }

    public function testUnsupportedGrantType()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'bar'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::INVALID_REQUEST, $e->getMessage());
            $this->assertEquals('Invalid or unsupported request.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeUnauthorizedForClient()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'refresh_token'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'baz', 'PHP_AUTH_PW' => 'secret']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals(ExceptionManagerInterface::UNAUTHORIZED_CLIENT, $e->getMessage());
            $this->assertEquals('The grant type "refresh_token" is unauthorized for this client.', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeAuthorizedForClient()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'refresh_token', 'refresh_token' => 'VALID_REFRESH_TOKEN'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"scope":"scope1 scope2 scope3","refresh_token":"[^"]+","foo":"bar"}', $response->getBody()->getContents());
    }

    public function testRefreshTokenParameterIsMissing()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'refresh_token'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('No "refresh_token" parameter found', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testRefreshTokenExpired()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'refresh_token', 'refresh_token' => 'EXPIRED_REFRESH_TOKEN'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_grant', $e->getMessage());
            $this->assertEquals('Refresh token has expired', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testWrongClient()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'refresh_token', 'refresh_token' => 'VALID_REFRESH_TOKEN'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_grant', $e->getMessage());
            $this->assertEquals('Invalid refresh token', $e->getDescription());
            $this->assertEquals(400, $e->getHttpCode());
        }
    }

    public function testGrantTypeAuthorizedForClientAndRefreshTokenCanStillBeUsed()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'refresh_token', 'refresh_token' => 'VALID_REFRESH_TOKEN'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"scope":"scope1 scope2 scope3","refresh_token":"[^"]+","foo":"bar"}', $response->getBody()->getContents());

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"scope":"scope1 scope2 scope3","refresh_token":"[^"]+","foo":"bar"}', $response->getBody()->getContents());
    }

    public function testGrantTypeAuthorizedForClientWithReducedScope()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'refresh_token', 'refresh_token' => 'VALID_REFRESH_TOKEN', 'scope' => 'scope2'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"scope":"scope2","refresh_token":"[^"]+","foo":"bar"}', $response->getBody()->getContents());
    }
}
