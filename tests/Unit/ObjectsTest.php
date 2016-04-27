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

use OAuth2\Client\Client;
use OAuth2\Exception\AuthenticateException;
use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\OpenIDConnect\IdToken;
use OAuth2\Test\Base;
use OAuth2\Test\Stub\TooManyRequestsException;
use OAuth2\Test\Stub\User;
use OAuth2\Token\AccessToken;
use OAuth2\Token\AuthCode;
use OAuth2\Token\RefreshToken;

/**
 * @group Objects
 */
class ObjectsTest extends Base
{
    public function testClient()
    {
        $client = new Client();
        $client->setGrantTypes(['foo', 'bar']);
        $client->setRedirectUris(['https://foo.com']);

        $this->assertEquals(['foo', 'bar'], $client->getGrantTypes());
        $this->assertEquals(['https://foo.com'], $client->getRedirectUris());
        $this->assertTrue($client->isGrantTypeAllowed('foo'));
        $this->assertFalse($client->isGrantTypeAllowed('baz'));
    }

    public function testIdToken()
    {
        $id_token = new IdToken();
        $id_token->setAccessTokenHash('foo');
        $id_token->setAuthorizationCodeHash('bar');
        $id_token->setClientPublicId('012');
        $id_token->setExpiresAt(time() + 3600);
        $id_token->setNonce('nonce');
        $id_token->setParameters(['foo' => 'bar']);
        $id_token->setResourceOwnerPublicId('resource_owner');
        $id_token->setScope([]);
        $id_token->setTokenType('type');

        $this->assertEquals('foo', $id_token->getAccessTokenHash());
        $this->assertEquals('bar', $id_token->getAuthorizationCodeHash());
        $this->assertEquals('012', $id_token->getClientPublicId());
        $this->assertEquals('nonce', $id_token->getNonce());
        $this->assertEquals('bar', $id_token->getParameter('foo'));
        $this->assertEquals('resource_owner', $id_token->getResourceOwnerPublicId());
        $this->assertEquals([], $id_token->getScope());
        $this->assertEquals('type', $id_token->getTokenType());
    }

    public function testUser()
    {
        $user = new User('user1', 'pass');
        $user->set('last_login_at', time() - 1000);

        $this->assertTrue($user->get('last_login_at') <= time() - 1000);
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
        new AuthenticateException('foo_error', 'foo_description', [], []);
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
        $access_token->setExpiresAt(0);
        $access_token->setToken('foo');
        $access_token->setTokenType('bar');

        $this->assertEquals([
            'access_token' => 'foo',
            'token_type'   => 'bar',
        ], $access_token->toArray());

        $this->assertFalse($access_token->hasExpired());
    }

    public function testRefreshTokenToArray()
    {
        $refresh_token = new RefreshToken();
        $refresh_token->setExpiresAt(0);
        $refresh_token->setToken('foo');

        $this->assertEquals('foo', $refresh_token->getToken());
        $this->assertFalse($refresh_token->hasExpired());
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

    public function testAuthenticateException()
    {
        $exception = new AuthenticateException('foo_error', 'foo_description', [], ['schemes' => ['Bearer realm="foo",charset=UTF-8']]);

        $this->assertNull($exception->getResponseBody());
        $this->assertEquals([
            'Cache-Control'    => 'no-store',
            'Pragma'           => 'no-cache',
            'WWW-Authenticate' => [
                'Bearer realm="foo",charset=UTF-8',
            ],
        ], $exception->getResponseHeaders());
    }

    public function testTooManyRequestsException()
    {
        try {
            throw $this->getExceptionManager()->getException('TooManyRequests', 'unauthorized_client', 'Only 300 requests/day');
        } catch (BaseExceptionInterface $e) {
            $this->assertInstanceOf(TooManyRequestsException::class, $e);
            $this->assertEquals('unauthorized_client', $e->getMessage());
            $this->assertEquals('Only 300 requests/day', $e->getDescription());
            $this->assertEquals(429, $e->getHttpCode());
        }
    }

    public function testTooManyRequestsException2()
    {
        try {
            throw $this->getExceptionManager()->getTooManyRequestsException('unauthorized_client', 'Only 300 requests/day');
        } catch (BaseExceptionInterface $e) {
            $this->assertInstanceOf(TooManyRequestsException::class, $e);
            $this->assertEquals('unauthorized_client', $e->getMessage());
            $this->assertEquals('Only 300 requests/day', $e->getDescription());
            $this->assertEquals(429, $e->getHttpCode());
        }
    }
}
