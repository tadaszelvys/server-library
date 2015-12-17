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

use OAuth2\Endpoint\Authorization;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Test\Base;
use Zend\Diactoros\Response;
use Zend\Diactoros\Uri;

/**
 * @group AuthorizationCodeGrantType
 */
class AuthCodeGrantTypeTest extends Base
{
    public function testRedirectUriParameterIsMissing()
    {
        $authorization = new Authorization();

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The "redirect_uri" parameter is missing. Add "redirect_uri" parameter or store redirect URIs to your client', $e->getDescription());
        }
    }

    public function testRedirectUriParameterWithFragment()
    {
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test#bad');

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The "redirect_uri" must not contain fragment', $e->getDescription());
        }
    }

    public function testRedirectUriParameterIsNotValid()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        if (null === $client) {
            $this->fail('Should throw an Exception');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/bade.redirect?URI');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The specified redirect URI is not valid', $e->getDescription());
        }
    }

    public function testResponseTypeParameterIsMissing()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Invalid "response_type" parameter or parameter is missing', $e->getDescription());
        }
    }

    public function testResponseTypeParameterIsNotSupported()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('bad_response_type');

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Response type "bad_response_type" is not supported by this server', $e->getDescription());
        }
    }

    public function testNonConfidentialClientMustRegisterAtLeastOneRedirectUri()
    {
        $client = $this->getClientManagerSupervisor()->getClient('oof');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('bad_response_type');

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('Non-confidential clients must register at least one redirect URI', $e->getDescription());
        }
    }

    public function testConfidentialClientWithRegisteredRedirectUriButUnsupportedResponseType()
    {
        $client = $this->getClientManagerSupervisor()->getClient('bar');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('bad_response_type');

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Response type "bad_response_type" is not supported by this server', $e->getDescription());
        }
    }

    public function testConfidentialClientWithUnregisteredRedirectUri()
    {
        $client = $this->getClientManagerSupervisor()->getClient('bar');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('https://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('bad_response_type');

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The specified redirect URI is not valid', $e->getDescription());
        }
    }

    public function testConfidentialClientUsingTokenResponseTypeWithoutRedirectUriRegistered()
    {
        $client = $this->getClientManagerSupervisor()->getClient('baz');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setClient($client);
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setResponseType('token');

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('Confidential clients must register at least one redirect URI when using "token" response type', $e->getDescription());
        }
    }

    public function testResponseTypeisNotAuthorizedForTheClient()
    {
        $client = $this->getClientManagerSupervisor()->getClient('baz');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('code');

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('unauthorized_client', $e->getMessage());
            $this->assertEquals('The response type "code" is unauthorized for this client.', $e->getDescription());
        }
    }

    public function testResourceOwnerDeniedAccess()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setClient($client);
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setResponseType('code');
        $authorization->setAuthorized(false);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertEquals('http://example.com/test?good=false&error=access_denied&error_description=The+resource+owner+denied+access+to+your+client&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Faccess_denied', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeSuccess()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('code');
        $authorization->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+$/', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeSuccessWithoutRedirectUri()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setClient($client);
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setResponseType('code');
        $authorization->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+$/', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeSuccessUsingAnotherRedirectUri()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('https://another.uri/callback');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('code');
        $authorization->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^https:\/\/another.uri\/callback\?code=[^"]+$/', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeSuccessWithState()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('code');
        $authorization->setState('0123456789');
        $authorization->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789$/', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeSuccessWithStateAndUnregisteredClient()
    {
        $client = $this->getClientManagerSupervisor()->getClient('**UNREGISTERED**--foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('code');
        $authorization->setState('0123456789');
        $authorization->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789$/', $response->getHeader('Location')[0]);

        $uri = new Uri($response->getHeader('Location')[0]);
        parse_str($uri->getQuery(), $result);
        $authcode = $this->getAuthCodeManager()->getAuthCode($result['code']);

        $this->assertTrue($authcode->getExpiresAt() <= time() + 100);
        $this->assertEquals('**UNREGISTERED**--foo', $authcode->getClientPublicId());

        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'client_id' => '**UNREGISTERED**--foo', 'redirect_uri' => 'http://example.com/test?good=false', 'code' => $authcode->getToken()], ['HTTPS' => 'on'], ['X-OAuth2-Unregistered-Client-ID' => '**UNREGISTERED**--foo']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","expires_in":[^"]+,"scope":"scope1 scope2","token_type":"Bearer"}', $response->getBody()->getContents());
    }

    /**
     * @see https://tools.ietf.org/html/rfc7636#appendix-B
     */
    public function testAuthcodeSuccessWithPKCEAndS256AndPublicClient()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('code');
        $authorization->setState('0123456789');
        $authorization->setQueryParams([
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'S256'
        ]);
        $authorization->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789$/', $response->getHeader('Location')[0]);

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
        $this->assertRegExp('{"access_token":"[^"]+","expires_in":[^"]+,"scope":"scope1 scope2","token_type":"Bearer"}', $response->getBody()->getContents());
    }

    public function testAuthcodeSuccessWithPKCEAndPlainAndPublicClient()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('code');
        $authorization->setState('0123456789');
        $authorization->setQueryParams([
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain'
        ]);
        $authorization->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789$/', $response->getHeader('Location')[0]);

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
        $this->assertRegExp('{"access_token":"[^"]+","expires_in":[^"]+,"scope":"scope1 scope2","token_type":"Bearer"}', $response->getBody()->getContents());
    }

    public function testAuthcodeSuccessWithPKCEAndDefaultMethodAndPublicClient()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('code');
        $authorization->setState('0123456789');
        $authorization->setQueryParams([
            'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
        ]);
        $authorization->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789$/', $response->getHeader('Location')[0]);

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
        $this->assertRegExp('{"access_token":"[^"]+","expires_in":[^"]+,"scope":"scope1 scope2","token_type":"Bearer"}', $response->getBody()->getContents());
    }

    public function testAuthcodeFailedWithBadCodeVerifier()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('code');
        $authorization->setState('0123456789');
        $authorization->setQueryParams([
            'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
        ]);
        $authorization->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789$/', $response->getHeader('Location')[0]);

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
    }

    public function testAuthcodeFailedWithPKCEBecauseCodeVerifierIsNotSet()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('code');
        $authorization->setState('0123456789');
        $authorization->setQueryParams([
            'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
        ]);
        $authorization->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789$/', $response->getHeader('Location')[0]);

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
    }

    public function testAuthcodeFailedWithPKCEBecauseCodeChallengeMethodIsNotSupported()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false');
        $authorization->setEndUser($this->getEndUserManager()->getEndUser('user1'));
        $authorization->setClient($client);
        $authorization->setResponseType('code');
        $authorization->setState('0123456789');
        $authorization->setQueryParams([
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'S512',
        ]);
        $authorization->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789$/', $response->getHeader('Location')[0]);

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
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'redirect_uri' => 'http://example.com/redirect_uri/'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo', 'XX-OAuth2-Public-Client-ID' => 'foo']);

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
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'code' => 'EXPIRED_AUTH_CODE', 'redirect_uri' => 'http://example.com/redirect_uri/'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

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
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'code' => 'VALID_AUTH_CODE', 'redirect_uri' => 'http://example.com/redirect_uri/bad/'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

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
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'code' => 'DO_NOT_EXIST', 'redirect_uri' => 'http://example.com/redirect_uri/bad/'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

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
        $request = $this->createRequest('/', 'POST', ['client_id' => 'foo', 'grant_type' => 'authorization_code', 'code' => 'VALID_AUTH_CODE_PUBLIC_CLIENT', 'redirect_uri' => 'http://example.com/redirect_uri/'], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","expires_in":[^"]+,"scope":"scope1 scope2","refresh_token":"[^"]+","token_type":"Bearer"}', $response->getBody()->getContents());

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(), true);

        $access_token = $this->getSimpleStringAccessTokenManager()->getAccessToken($json['access_token']);

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $access_token);
        $this->assertTrue($this->getSimpleStringAccessTokenManager()->isAccessTokenValid($access_token));
    }

    public function testPrivateClientGranted()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', ['grant_type' => 'authorization_code', 'code' => 'VALID_AUTH_CODE', 'redirect_uri' => 'http://example.com/redirect_uri/'], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret']);

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","expires_in":[^"]+,"scope":"scope1 scope2","refresh_token":"[^"]+","token_type":"Bearer"}', $response->getBody()->getContents());

        $response->getBody()->rewind();
        $json = json_decode($response->getBody()->getContents(), true);

        $access_token = $this->getSimpleStringAccessTokenManager()->getAccessToken($json['access_token']);

        $this->assertInstanceOf('\OAuth2\Token\AccessTokenInterface', $access_token);
        $this->assertTrue($this->getSimpleStringAccessTokenManager()->isAccessTokenValid($access_token));
    }
}
