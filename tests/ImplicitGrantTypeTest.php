<?php

namespace OAuth2\Test;

use OAuth2\Endpoint\Authorization;
use OAuth2\Exception\BaseExceptionInterface;

/**
 * @group ImplicitGrantType
 */
class ImplicitGrantTypeTest extends Base
{
    public function testRedirectUriParameterIsMissing()
    {
        $authorization = new Authorization();

        try {
            $this->getAuthorizationEndpoint()->authorize($authorization);
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

        try {
            $this->getAuthorizationEndpoint()->authorize($authorization);
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
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=true')
                      ->setClient($client);

        try {
            $this->getAuthorizationEndpoint()->authorize($authorization);
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

        try {
            $this->getAuthorizationEndpoint()->authorize($authorization);
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

        try {
            $this->getAuthorizationEndpoint()->authorize($authorization);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Response type "bad_response_type" is not supported by this server', $e->getDescription());
        }
    }

    public function testNonConfidentialClientMustRegisterAtLeastOneRedirectUri()
    {
        $client = $this->getClientManagerSupervisor()->getClient('oof');
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('bad_response_type');

        try {
            $this->getAuthorizationEndpoint()->authorize($authorization);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_client', $e->getMessage());
            $this->assertEquals('Non-confidential clients must register at least one redirect URI', $e->getDescription());
        }
    }

    public function testResponseTypeisNotAuthorizedForTheClient()
    {
        $client = $this->getClientManagerSupervisor()->getClient('fii');
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('token');

        try {
            $this->getAuthorizationEndpoint()->authorize($authorization);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('unauthorized_client', $e->getMessage());
            $this->assertEquals('The response type "token" is unauthorized for this client.', $e->getDescription());
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
                      ->setAuthorized(false)
                      ->setResponseType('token');

        $response = $this->getAuthorizationEndpoint()->authorize($authorization);
        $this->assertEquals('http://example.com/test?good=false#error=access_denied&error_description=The+resource+owner+denied+access+to+your+client&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Faccess_denied', $response->headers->get('Location'));
    }

    public function testAccessTokenSuccess()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('token')
                      ->setAuthorized(true);

        $response = $this->getAuthorizationEndpoint()->authorize($authorization);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&expires_in=3600&scope=scope1\+scope2&token_type=Bearer$/', $response->headers->get('Location'));
    }

    public function testAccessTokenSuccessWithState()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (is_null($client)) {
            $this->fail('Unable to get client');
            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
                      ->setClient($client)
                      ->setResponseType('token')
                      ->setState('0123456789')
                      ->setAuthorized(true);

        $response = $this->getAuthorizationEndpoint()->authorize($authorization);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&expires_in=3600&scope=scope1\+scope2&token_type=Bearer&state=[^"]+$/', $response->headers->get('Location'));
    }
}
