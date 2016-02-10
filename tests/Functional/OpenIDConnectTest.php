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
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Uri;

/**
 * @group OpenIDConnect
 */
class OpenIDConnectTest extends Base
{
    public function testAuthcodeSuccessWithIdToken()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => '**UNREGISTERED**--foo',
            'response_type'         => 'code',
            'scope'                 => 'openid',
            'nonce'                 => 'foo/bar',
            'state'                 => '0123456789',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getEndUserManager()->getEndUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789$/', $response->getHeader('Location')[0]);

        $uri = new Uri($response->getHeader('Location')[0]);
        parse_str($uri->getQuery(), $result);
        $authcode = $this->getAuthCodeManager()->getAuthCode($result['code']);

        $this->assertTrue($authcode->getExpiresAt() <= time() + 100);
        $this->assertEquals('**UNREGISTERED**--foo', $authcode->getClientPublicId());

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'client_id' => '**UNREGISTERED**--foo', 'redirect_uri' => 'http://example.com/test?good=false', 'code' => $authcode->getToken(), 'code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'], ['HTTPS' => 'on'], ['X-OAuth2-Unregistered-Client-ID' => '**UNREGISTERED**--foo']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"foo":"bar","scope":"openid","id_token":"[^"]+"}', $response->getBody()->getContents());

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(), true);

        $id_token = $this->getIdTokenManager()->getIdToken($json['id_token']);

        $this->assertInstanceOf('\OAuth2\Token\IdTokenInterface', $id_token);

        $this->assertEquals('My Authorization Server', $id_token->getJWS()->getClaim('iss'));
        $this->assertEquals('**UNREGISTERED**--foo', $id_token->getJWS()->getClaim('aud'));
        $this->assertEquals('user1', $id_token->getJWS()->getClaim('sub'));
        $this->assertEquals('foo/bar', $id_token->getJWS()->getClaim('nonce'));
        $this->assertTrue($id_token->getJWS()->hasClaim('iat'));
        $this->assertTrue($id_token->getJWS()->hasClaim('nbf'));
        $this->assertTrue($id_token->getJWS()->hasClaim('exp'));
        $this->assertTrue($id_token->getJWS()->hasClaim('auth_time'));
        $this->assertTrue($id_token->getJWS()->hasClaim('at_hash'));
        $this->assertTrue($id_token->getJWS()->hasClaim('c_hash'));
    }

    public function testCodeTokenSuccess()
    {
        $this->markTestIncomplete('ID Token not yet implemented');

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'code token',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
        ]);
        $authorization = $this->getAuthorizationFactory()->createFromRequest(
            $request,
            $this->getEndUserManager()->getEndUser('user1'),
            true
        );

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=scope1\+scope2&code=[^"]+&id_token=[^"]+$/', $response->getHeader('Location')[0]);
        $values = parse_url($response->getHeader('Location')[0]);
        parse_str($values['fragment'], $params);

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['client_id' => 'foo', 'grant_type' => 'authorization_code', 'code' => $params['code'], 'redirect_uri' => 'http://example.com/test?good=false', 'code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[^"]+,"refresh_token":"[^"]+","scope":"scope1 scope2"}', $response->getBody()->getContents());

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(), true);

        $access_token = $this->getJWTAccessTokenManager()->getAccessToken($json['access_token']);

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $access_token);
        $this->assertTrue($this->getJWTAccessTokenManager()->isAccessTokenValid($access_token));
    }

    public function testCodeIdTokenTokenSuccess()
    {
        $this->markTestIncomplete('ID Token not yet implemented');

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

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&id_token=[^"]+&access_token=[^"]+&token_type=Bearer&expires_in=[\d]+&scope=scope1\+scope2$/', $response->getHeader('Location')[0]);
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
        $this->assertEquals(1, count($this->getNoneListener()->getAccessTokens()));

        $access_tokens = $this->getNoneListener()->getAccessTokens();
        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $access_tokens[0]);
    }

    public function testUserInfoSuccess()
    {
        $request = $this->createRequest('/', 'GET', [], ['HTTPS' => 'on'], ['authorization' => 'Bearer USER_INFO']);

        $response = new Response();
        $this->getUserInfoEndpoint()->getUserInfo($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('{"sub":"user1"}', $response->getBody()->getContents());
    }
}
