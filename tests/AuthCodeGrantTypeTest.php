<?php

namespace OAuth2\Test;

use OAuth2\Endpoint\Authorization;
use OAuth2\Exception\BaseExceptionInterface;
use Zend\Diactoros\Response;

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
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        if (is_null($client)) {
            $this->fail('Should throw an Exception');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/bade.redirect?URI')
                      ->setClient($client);

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
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client);

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
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('bad_response_type');

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
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('bad_response_type');

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
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('bad_response_type');

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
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('https://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('bad_response_type');

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
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setClient($client)
                      ->setResponseType('token');

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
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('code');

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
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('code')
                      ->setAuthorized(false);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertEquals('http://example.com/test?good=false&error=access_denied&error_description=The+resource+owner+denied+access+to+your+client&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Faccess_denied', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeSuccess()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('code')
                      ->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+$/', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeSuccessWithoutRedirectUri()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setClient($client)
                      ->setResponseType('code')
                      ->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+$/', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeSuccessUsingAnotherRedirectUri()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('https://another.uri/callback')
                      ->setClient($client)
                      ->setResponseType('code')
                      ->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^https:\/\/another.uri\/callback\?code=[^"]+$/', $response->getHeader('Location')[0]);
    }

    public function testAuthcodeSuccessWithState()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('code')
                      ->setState('0123456789')
                      ->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false&code=[^"]+&state=0123456789$/', $response->getHeader('Location')[0]);
    }

    public function testPublicClientWithoutPublicId()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo'], http_build_query(['grant_type' => 'authorization_code', 'redirect_uri' => 'http://example.com/redirect_uri/']));

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('The client_id parameter is required for non-confidential clients.', $e->getDescription());
        }
    }

    public function testParameterCodeIsMissing()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on'], ['X-OAuth2-Public-Client-ID' => 'foo'], http_build_query(['grant_type' => 'authorization_code', 'client_id' => 'foo', 'redirect_uri' => 'http://example.com/redirect_uri/']));

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
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'baz', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['grant_type' => 'authorization_code', 'redirect_uri' => 'http://example.com/redirect_uri/']));

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
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['grant_type' => 'authorization_code', 'code' => 'EXPIRED_AUTH_CODE', 'redirect_uri' => 'http://example.com/redirect_uri/']));

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
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['grant_type' => 'authorization_code', 'code' => 'VALID_AUTH_CODE', 'redirect_uri' => 'http://example.com/redirect_uri/bad/']));

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
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['grant_type' => 'authorization_code', 'code' => 'DO_NOT_EXIST', 'redirect_uri' => 'http://example.com/redirect_uri/bad/']));

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
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'baz', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['grant_type' => 'authorization_code', 'code' => 'VALID_AUTH_CODE', 'redirect_uri' => 'http://example.com/redirect_uri/bad/']));

        try {
            $this->getTokenEndpoint()->getAccessToken($request, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_grant', $e->getMessage());
            $this->assertEquals("Code doesn't exist or is invalid for the client.", $e->getDescription());
        }
    }

    public function testClientGranted()
    {
        $response = new Response();
        $request = $this->createRequest('/', 'POST', [], ['HTTPS' => 'on', 'PHP_AUTH_USER' => 'bar', 'PHP_AUTH_PW' => 'secret'], [], http_build_query(['grant_type' => 'authorization_code', 'code' => 'VALID_AUTH_CODE', 'redirect_uri' => 'http://example.com/redirect_uri/']));

        $this->getTokenEndpoint()->getAccessToken($request, $response);
        $response->getBody()->rewind();

        $this->assertEquals('application/json', $response->getHeader('Content-Type')[0]);
        $this->assertEquals('no-store, private', $response->getHeader('Cache-Control')[0]);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('no-cache', $response->getHeader('Pragma')[0]);
        $this->assertRegExp('{"access_token":"[^"]+","expires_in":[^"]+,"scope":"scope1 scope2","refresh_token":"[^"]+","token_type":"Bearer"}', $response->getBody()->getContents());
    }
}
