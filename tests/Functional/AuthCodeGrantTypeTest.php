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
use OAuth2\Test\Base;
use OAuth2\Token\AccessTokenInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;
use Zend\Diactoros\Uri;

/**
 * @group AuthorizationCodeGrantType
 */
class AuthCodeGrantTypeTest extends Base
{
    public function testClientIdParameterIsMissing()
    {
        $request = new ServerRequest();
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $response->getBody()->rewind();
        $this->assertEquals('{"error":"invalid_request","error_description":"Parameter \"client_id\" missing or invalid.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testResponseTypeParameterIsMissing()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'client_id' => 'foo',
            'state'     => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $response->getBody()->rewind();
        $this->assertEquals('{"error":"invalid_request","error_description":"The parameter \"response_type\" is mandatory.","error_uri":"https:\/\/foo.test\/Error\/BadRequest\/invalid_request"}', $response->getBody()->getContents());
    }

    public function testRedirectUriParameterIsNotValid()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'response_type' => 'token',
            'redirect_uri'  => 'http://example.com/bad.redirect?URI',
            'client_id'     => 'foo',
            'state'         => '0123456',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/bad.redirect?URI#error=invalid_request&error_description=The+specified+redirect+URI+is+not+valid.&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request&state=0123456', $response->getHeader('Location')[0]);
    }

    public function testStateParameterIsMissing()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'response_type' => 'token',
            'redirect_uri'  => 'http://example.com/bad.redirect?URI',
            'client_id'     => 'foo',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/bad.redirect?URI#error=invalid_request&error_description=The+parameter+%22state%22+is+mandatory.&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request', $response->getHeader('Location')[0]);
    }

    public function testResponseTypeParameterIsNotSupported()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'bad_response_type',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/test?good=false&error=invalid_request&error_description=Response+type+%22bad_response_type%22+is+not+supported+by+this+server&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request&state=0123456789#', $response->getHeader('Location')[0]);
    }

    public function testNonConfidentialClientMustRegisterAtLeastOneRedirectUri()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'oof',
            'response_type' => 'none',
            'state'         => '0123456',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/test?good=false&error=invalid_request&error_description=Non-confidential+clients+must+register+at+least+one+redirect+URI.&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request&state=0123456#', $response->getHeader('Location')[0]);
    }

    public function testConfidentialClientWithRegisteredRedirectUriButUnsupportedResponseType()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'bar',
            'response_type' => 'bad_response_type',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/test?good=false&error=invalid_request&error_description=Response+type+%22bad_response_type%22+is+not+supported+by+this+server&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request&state=0123456789#', $response->getHeader('Location')[0]);
    }

    public function testConfidentialClientWithUnregisteredRedirectUri()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'https://example.com/test?good=false',
            'client_id'     => 'bar',
            'response_type' => 'none',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('https://example.com/test?good=false&error=invalid_request&error_description=The+specified+redirect+URI+is+not+valid.&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request&state=0123456789#', $response->getHeader('Location')[0]);
    }

    public function testConfidentialClientUsingTokenResponseTypeWithoutRedirectUriRegistered()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'baz',
            'response_type' => 'token',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/test?good=false#error=invalid_request&error_description=Confidential+clients+must+register+at+least+one+redirect+URI+when+using+%22token%22+response+type.&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Finvalid_request&state=0123456789', $response->getHeader('Location')[0]);
    }

    public function testResponseTypeIsNotAuthorizedForTheClient()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'baz',
            'response_type' => 'code',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($request, $response);
        $this->assertEquals('http://example.com/test?good=false&error=unauthorized_client&error_description=The+response+type+%22code%22+is+unauthorized+for+this+client.&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Funauthorized_client&state=0123456789#', $response->getHeader('Location')[0]);
    }

    public function testResourceOwnerDeniedAccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'code',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(false);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertEquals('http://example.com/test?good=false&error=access_denied&error_description=The+resource+owner+denied+access+to+your+client&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Faccess_denied&state=0123456789#', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeSuccess()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'Mufasa',
            'response_type' => 'code',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeSuccessToLocalHostAndSecuredRedirectUriEnforced()
    {
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://127.0.0.1/',
            'client_id'     => 'Mufasa',
            'response_type' => 'code',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/127.0.0.1\/\?code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeAuthorizedToSupportedURN()
    {
        $this->getAuthorizationCodeGrantType()->allowPublicClients();

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'urn:ietf:wg:oauth:2.0:oob:auto',
            'client_id'     => 'foo',
            'response_type' => 'code',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^urn\:\/\/ietf\:wg\:oauth\:2.0\:oob\:auto\?code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);

        $this->getAuthorizationCodeGrantType()->disallowPublicClients();
    }

    public function testAuthcodeSuccessUsingAnotherRedirectUri()
    {
        $this->getAuthorizationCodeGrantType()->allowPublicClients();

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'https://another.uri/callback',
            'client_id'     => 'foo',
            'response_type' => 'code',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^https:\/\/another.uri\/callback\?code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);

        $this->getAuthorizationCodeGrantType()->disallowPublicClients();
    }

    public function testAuthcodeSuccessWithState()
    {
        $this->getAuthorizationCodeGrantType()->allowPublicClients();

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'  => 'http://example.com/test?good=false',
            'client_id'     => 'foo',
            'response_type' => 'code',
            'state'         => '0123456789',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);

        $this->getAuthorizationCodeGrantType()->disallowPublicClients();
    }

    /**
     * @see https://tools.ietf.org/html/rfc7636#appendix-B
     */
    public function testAuthcodeSuccessWithPKCEAndS256AndPublicClient()
    {
        $this->getAuthorizationCodeGrantType()->allowPublicClients();

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'code',
            'state'                 => '0123456789',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'S256',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);

        $uri = new Uri($response->getHeader('Location')[0]);
        parse_str($uri->getQuery(), $result);
        $authcode = $this->getAuthCodeManager()->getAuthCode($result['code']);

        $this->assertTrue($authcode->getExpiresAt() <= time() + 100);
        $this->assertEquals('foo', $authcode->getClientPublicId());

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'client_id' => 'foo', 'redirect_uri' => 'http://example.com/test?good=false', 'code' => $authcode->getToken(), 'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"scope":"scope1 scope2","foo":"bar"}', $response->getBody()->getContents());

        $this->getAuthorizationCodeGrantType()->disallowPublicClients();
    }

    public function testAuthcodeSuccessWithPKCEAndPlainAndPublicClient()
    {
        $this->getAuthorizationCodeGrantType()->allowPublicClients();

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'code',
            'state'                 => '0123456789',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);

        $uri = new Uri($response->getHeader('Location')[0]);
        parse_str($uri->getQuery(), $result);
        $authcode = $this->getAuthCodeManager()->getAuthCode($result['code']);

        $this->assertTrue($authcode->getExpiresAt() <= time() + 100);
        $this->assertEquals('foo', $authcode->getClientPublicId());

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'client_id' => 'foo', 'redirect_uri' => 'http://example.com/test?good=false', 'code' => $authcode->getToken(), 'code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"scope":"scope1 scope2","foo":"bar"}', $response->getBody()->getContents());

        $this->getAuthorizationCodeGrantType()->disallowPublicClients();
    }

    public function testAuthcodeSuccessWithPKCEAndDefaultMethodAndPublicClient()
    {
        $this->getAuthorizationCodeGrantType()->allowPublicClients();

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'code',
            'state'                 => '0123456789',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);

        $uri = new Uri($response->getHeader('Location')[0]);
        parse_str($uri->getQuery(), $result);
        $authcode = $this->getAuthCodeManager()->getAuthCode($result['code']);

        $this->assertTrue($authcode->getExpiresAt() <= time() + 100);
        $this->assertEquals('foo', $authcode->getClientPublicId());

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'client_id' => 'foo', 'redirect_uri' => 'http://example.com/test?good=false', 'code' => $authcode->getToken(), 'code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"scope":"scope1 scope2","foo":"bar"}', $response->getBody()->getContents());

        $this->getAuthorizationCodeGrantType()->disallowPublicClients();
    }

    public function testAuthcodeFailedWithBadCodeVerifier()
    {
        $this->getAuthorizationCodeGrantType()->allowPublicClients();
        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'code',
            'state'                 => '0123456789',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);

        $uri = new Uri($response->getHeader('Location')[0]);
        parse_str($uri->getQuery(), $result);
        $authcode = $this->getAuthCodeManager()->getAuthCode($result['code']);

        $this->assertTrue($authcode->getExpiresAt() <= time() + 100);
        $this->assertEquals('foo', $authcode->getClientPublicId());

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'client_id' => 'foo', 'redirect_uri' => 'http://example.com/test?good=false', 'code' => $authcode->getToken(), 'code_verifier' => 'Bad PKCE'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Invalid parameter "code_verifier".', $e->getDescription());
        }
        $this->getAuthorizationCodeGrantType()->disallowPublicClients();
    }

    public function testAuthcodeFailedWithPKCEBecauseCodeVerifierIsNotSet()
    {
        $this->getAuthorizationCodeGrantType()->allowPublicClients();

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'code',
            'state'                 => '0123456789',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);

        $uri = new Uri($response->getHeader('Location')[0]);
        parse_str($uri->getQuery(), $result);
        $authcode = $this->getAuthCodeManager()->getAuthCode($result['code']);

        $this->assertTrue($authcode->getExpiresAt() <= time() + 100);
        $this->assertEquals('foo', $authcode->getClientPublicId());

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'client_id' => 'foo', 'redirect_uri' => 'http://example.com/test?good=false', 'code' => $authcode->getToken()], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The parameter "code_verifier" is required.', $e->getDescription());
        }

        $this->getAuthorizationCodeGrantType()->disallowPublicClients();
    }

    public function testAuthcodeFailedWithPKCEBecauseCodeChallengeMethodIsNotSupported()
    {
        $this->getAuthorizationCodeGrantType()->allowPublicClients();

        $request = new ServerRequest();
        $request = $request->withQueryParams([
            'redirect_uri'          => 'http://example.com/test?good=false',
            'client_id'             => 'foo',
            'response_type'         => 'code',
            'state'                 => '0123456789',
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'S512',
        ]);
        $response = new Response();
        $this->getAuthorizationEndpoint()->setCurrentUser('user1');
        $this->getAuthorizationEndpoint()->setIsAuthorized(true);
        $this->getAuthorizationEndpoint()->authorize($request, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789#$/', $response->getHeader('Location')[0]);

        $uri = new Uri($response->getHeader('Location')[0]);
        parse_str($uri->getQuery(), $result);
        $authcode = $this->getAuthCodeManager()->getAuthCode($result['code']);

        $this->assertTrue($authcode->getExpiresAt() <= time() + 100);
        $this->assertEquals('foo', $authcode->getClientPublicId());

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'client_id' => 'foo', 'redirect_uri' => 'http://example.com/test?good=false', 'code' => $authcode->getToken()], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Unsupported code challenge method "S512".', $e->getDescription());
        }

        $this->getAuthorizationCodeGrantType()->disallowPublicClients();
    }

    public function testPublicClientWithoutPublicId()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'redirect_uri' => 'http://example.com/redirect_uri/'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The client_id parameter is required for non-confidential clients.', $e->getDescription());
        }
    }

    public function testPublicClientWithMultipleAuthenticationProcess()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'redirect_uri' => 'http://example.com/redirect_uri/'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Only one authentication method may be used to authenticate the client.', $e->getDescription());
        }
    }

    public function testParameterCodeIsMissing()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'client_id' => 'foo', 'redirect_uri' => 'http://example.com/redirect_uri/'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Missing parameter. "code" is required.', $e->getDescription());
        }
    }

    public function testParameterCodeIsMissing2()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'redirect_uri' => 'http://example.com/redirect_uri/'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'baz', 'PHP_AUTH_PW' => 'secret']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Missing parameter. "code" is required.', $e->getDescription());
        }
    }

    public function testExpiredAuthcode()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'code' => 'EXPIRED_AUTH_CODE', 'redirect_uri' => 'http://example.com/redirect_uri/'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_grant', $e->getMessage());
            $this->assertEquals('The authorization code has expired.', $e->getDescription());
        }
    }

    public function testRedirectUriMismatch()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'code' => 'VALID_AUTH_CODE', 'redirect_uri' => 'http://example.com/redirect_uri/bad/'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The redirect URI is missing or does not match.', $e->getDescription());
        }
    }

    public function testAuthCodeDoesNotExists()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'code' => 'DO_NOT_EXIST', 'redirect_uri' => 'http://example.com/redirect_uri/bad/'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_grant', $e->getMessage());
            $this->assertEquals("Code doesn't exist or is invalid for the client.", $e->getDescription());
        }
    }

    public function testAuthCodeNotForTheClient()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'code' => 'VALID_AUTH_CODE', 'redirect_uri' => 'http://example.com/redirect_uri/bad/'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'baz', 'PHP_AUTH_PW' => 'secret']);

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_grant', $e->getMessage());
            $this->assertEquals("Code doesn't exist or is invalid for the client.", $e->getDescription());
        }
    }

    public function testPublicClientGranted()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['client_id' => 'foo', 'grant_type' => 'authorization_code', 'code' => 'VALID_AUTH_CODE_PUBLIC_CLIENT', 'redirect_uri' => 'http://example.com/redirect_uri/', 'code_verifier' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();
        $body = $response->getBody()->getContents();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"scope":"scope1 scope2","refresh_token":"[^"]+","foo":"bar"}', $body);

        $json = json_decode($body, true);

        $access_token = $this->getJWTAccessTokenManager()->getAccessToken($json['access_token']);

        $this->assertInstanceOf(AccessTokenInterface::class, $access_token);
        $this->assertTrue($this->getJWTAccessTokenManager()->isAccessTokenValid($access_token));
    }

    public function testPrivateClientGranted()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'code' => 'VALID_AUTH_CODE', 'redirect_uri' => 'http://example.com/redirect_uri/'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'Mufasa', 'PHP_AUTH_PW' => 'Circle Of Life']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","token_type":"Bearer","expires_in":[0-9]+,"scope":"scope1 scope2","refresh_token":"[^"]+","foo":"bar"}', $response->getBody()->getContents());

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(), true);

        $access_token = $this->getJWTAccessTokenManager()->getAccessToken($json['access_token']);

        $this->assertInstanceOf(AccessTokenInterface::class, $access_token);
        $this->assertTrue($this->getJWTAccessTokenManager()->isAccessTokenValid($access_token));
    }
}
