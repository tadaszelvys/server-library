<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Unit;

use OAuth2\Client\PublicClient;
use OAuth2\Exception\AuthenticateException;
use OAuth2\ResourceServer\ResourceServer;
use OAuth2\Scope\Scope;
use OAuth2\Test\Base;
use OAuth2\Test\Stub\EndUser;
use OAuth2\Token\AccessToken;
use OAuth2\Token\AuthCode;
use OAuth2\Token\IdToken;

/**
 * @group Objects
 */
class ObjectsTest extends Base
{

    public function testClient()
    {
        $client = new PublicClient();
        $client->setAllowedGrantTypes(['foo', 'bar']);
        $client->addAllowedGrantType('baz');
        $client->removeAllowedGrantType('baz');
        $client->setRedirectUris(['https://foo.com']);
        $client->addRedirectUri('https://baz.com');
        $client->removeRedirectUri('https://baz.com');

        $this->assertEquals('public_client', $client->getType());
        $this->assertEquals(['foo', 'bar'], $client->getAllowedGrantTypes());
        $this->assertEquals(['https://foo.com'], $client->getRedirectUris());
        $this->assertTrue($client->hasRedirectUri('https://foo.com'));
        $this->assertFalse($client->hasRedirectUri('https://bar.com'));
        $this->assertTrue($client->isAllowedGrantType('foo'));
        $this->assertFalse($client->isAllowedGrantType('baz'));
    }

    public function testScope()
    {
        $scope = new Scope('foo');

        $this->assertEquals('foo', $scope->getName());
    }

    public function testScopeThroughScopeManager()
    {
        $scope = $this->getScopeManager()->getScope('foo');

        $this->assertEquals('foo', $scope->getName());
    }

    public function testScopesThroughScopeManager()
    {
        $scopes = $this->getScopeManager()->convertToScope(['foo']);

        $this->assertTrue(is_array($scopes));
        $this->assertEquals(1, count($scopes));
        $this->assertEquals('foo', $scopes[0]->getName());
    }

    public function testIdToken()
    {
        $id_token = new IdToken();
        $id_token->setAccessTokenHash('foo');
        $id_token->setAuthorizationCodeHash('bar');
        $id_token->setClientPublicId('012');
        $id_token->setExpiresAt(time()+3600);
        $id_token->setNonce('nonce');
        $id_token->setParameters(['foo'=>'bar']);
        $id_token->setResourceOwnerPublicId('resource_owner');
        $id_token->setScope([]);

        $this->assertEquals('foo', $id_token->getAccessTokenHash());
        $this->assertEquals('bar', $id_token->getAuthorizationCodeHash());
        $this->assertEquals('012', $id_token->getClientPublicId());
        $this->assertEquals('nonce', $id_token->getNonce());
        $this->assertEquals('bar', $id_token->getParameter('foo'));
        $this->assertEquals('resource_owner', $id_token->getResourceOwnerPublicId());
        $this->assertEquals([], $id_token->getScope());
    }

    public function testAuthorizationFactory()
    {
        $this->assertTrue($this->getAuthorizationFactory()->isRequestParameterSupported());
        $this->assertTrue($this->getAuthorizationFactory()->isRequestUriParameterSupported());
    }

    public function testEndUser()
    {
        $user = new EndUser('user1', 'pass');
        $user->setLastLoginAt(time() - 1000);

        $this->assertEquals('end_user', $user->getType());
        $this->assertTrue($user->getLastLoginAt() <= time() - 1000);
        $this->assertEquals('user1', $user->getUsername());
    }

    public function testAuthCodeQueryParams()
    {
        $auth_code = new AuthCode();
        $auth_code->setQueryParams(['foo' => 'bar']);

        $this->assertEquals(['foo' => 'bar'], $auth_code->getQueryParams());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage schemes_not_defined
     */
    public function testAuthenticateExceptionConstructionFailed()
    {
        new AuthenticateException('foo_error', 'foo_description', 'https://foo.com/error', []);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Parameter with key "foo" does not exist.
     */
    public function testAccessTokenParameterDoesNotExist()
    {
        $access_token = new AccessToken();
        $access_token->getParameter('foo');
    }

    public function testAccessTokenParameterExists()
    {
        $access_token = new AccessToken();
        $access_token->setParameters([
            'foo' => 'bar',
        ]);

        $this->assertEquals('bar', $access_token->getParameter('foo'));
    }

    public function testAccessTokenToArray()
    {
        $access_token = new AccessToken();

        $this->assertEquals([
            'access_token' => null,
            'token_type'   => null,
            'expires_in'   => 0,
        ], $access_token->toArray());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Parameter with key "foo" does not exist.
     */
    public function testAccessTokenParameterUnset()
    {
        $access_token = new AccessToken();
        $access_token->setParameters([
            'foo' => 'bar',
        ]);
        $access_token->unsetParameter('foo');
        $access_token->getParameter('foo');
    }

    /**
     * @expectedException \OAuth2\Exception\InternalServerErrorException
     * @expectedExceptionMessage server_error
     */
    public function testAccessTokenTypeAlreadyExist()
    {
        $this->getTokenTypeManager()->addTokenType($this->getBearerAccessTokenType());
    }

    public function testResourceServer()
    {
        $rs = new ResourceServer();
        $rs->setAllowedGrantTypes(['foo']);
        $rs->setPublicId('bar');
        $rs->setType(['plic']);
        $rs->addAllowedGrantType('foo');
        $rs->removeAllowedGrantType('bar');
        $rs->setAllowedIpAddresses(['127.0.0.1']);

        $this->assertFalse($rs->isAllowedGrantType('foo'));
        $this->assertFalse($rs->isAllowedGrantType('bar'));
        $this->assertEquals([], $rs->getAllowedGrantTypes());
        $this->assertEquals(['127.0.0.1'], $rs->getAllowedIpAddresses());
        $this->assertEquals([], $rs->getAllowedGrantTypes());
        $this->assertEquals('bar', $rs->getPublicId());
        $this->assertNull($rs->getServerName());
        $this->assertEquals('resource_server', $rs->getType());
    }

    public function testAuthenticateException()
    {
        $exception = new AuthenticateException('foo_error', 'foo_description', 'https://foo.com/error', ['schemes' => ['Bearer realm="foo",charset=UTF-8']]);

        $this->assertNull($exception->getResponseBody());
        $this->assertEquals([
            'Content-Type'     => 'application/json',
            'Cache-Control'    => 'no-store',
            'Pragma'           => 'no-cache',
            'WWW-Authenticate' => [
                'Bearer realm="foo",charset=UTF-8',
            ],
        ], $exception->getResponseHeaders());
    }
}
