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
use PHPHtmlParser\Dom;
use Zend\Diactoros\Response;

/**
 * @group ImplicitGrantType
 */
class ImplicitGrantTypeTest extends Base
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
        $authorization
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
            ->setRedirectUri('http://example.com/test#bad');

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
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=true')
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
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
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
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
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
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
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
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

    public function testResponseTypeisNotAuthorizedForTheClient()
    {
        $client = $this->getClientManagerSupervisor()->getClient('fii');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
            ->setClient($client)
            ->setResponseType('token');

        $response = new Response();
        try {
            $this->getAuthorizationEndpoint()->authorize($authorization, $response);
            $this->fail('Should throw an Exception');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('unauthorized_client', $e->getMessage());
            $this->assertEquals('The response type "token" is unauthorized for this client.', $e->getDescription());
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
        $authorization->setRedirectUri('http://example.com/test?good=false')
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
            ->setClient($client)
            ->setAuthorized(false)
            ->setResponseType('token');

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertEquals('http://example.com/test?good=false#error=access_denied&error_description=The+resource+owner+denied+access+to+your+client&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Faccess_denied', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccess()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
            ->setClient($client)
            ->setResponseType('token')
            ->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&expires_in=3600&scope=scope1\+scope2&token_type=Bearer$/', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccessWithState()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
            ->setClient($client)
            ->setResponseType('token')
            ->setState('0123456789')
            ->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#access_token=[^"]+&expires_in=3600&scope=scope1\+scope2&token_type=Bearer&state=[^"]+$/', $response->getHeader('Location')[0]);
    }

    public function testAccessTokenSuccessWithStateAndForPoostResponseMode()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
            ->setClient($client)
            ->setResponseType('token')
            ->setState('0123456789')
            ->setResponseMode('form_post')
            ->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);

        $response->getBody()->rewind();
        $content = $response->getBody()->getContents();

        $dom = new Dom();
        $dom->load($content);
        $inputs = $dom->find('input');

        $this->assertNotNull($inputs);
        $this->assertEquals(5, count($inputs));
    }
}
