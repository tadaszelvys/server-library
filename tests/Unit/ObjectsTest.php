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
use OAuth2\OpenIdConnect\IdToken;
use OAuth2\Test\Base;
use OAuth2\Test\Stub\TooManyRequestsException;
use OAuth2\Test\Stub\UserAccount;
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
        $client->set('grant_types', ['foo', 'bar']);
        $client->set('redirect_uris', ['https://foo.com']);

        $this->assertEquals(['foo', 'bar'], $client->get('grant_types'));
        $this->assertEquals(['https://foo.com'], $client->get('redirect_uris'));
        $this->assertTrue($client->isGrantTypeAllowed('foo'));
        $this->assertFalse($client->isGrantTypeAllowed('baz'));

        $client->remove('grant_types');
        $this->assertFalse($client->has('grant_types'));
    }

    /**
     * @expectedException \BadMethodCallException
     * @expectedException 'Method "sayHello" does not exist.'
     */
    public function testClientBadCall()
    {
        $client = new Client();
        $client->sayHello();
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
        $id_token->setUserAccountPublicId('user_account');
        $id_token->setScope([]);

        $this->assertEquals('foo', $id_token->getAccessTokenHash());
        $this->assertEquals('bar', $id_token->getAuthorizationCodeHash());
        $this->assertEquals('012', $id_token->getClientPublicId());
        $this->assertEquals('nonce', $id_token->getNonce());
        $this->assertEquals('bar', $id_token->getParameter('foo'));
        $this->assertEquals('resource_owner', $id_token->getResourceOwnerPublicId());
        $this->assertEquals('user_account', $id_token->getUserAccountPublicId());
        $this->assertEquals([], $id_token->getScope());
    }

    public function testUserAccount()
    {
        $user = new UserAccount('user1', 'pass', 'real_user1_public_id');
        $user->set('last_login_at', time() - 1000);

        $this->assertTrue($user->get('last_login_at') <= time() - 1000);
        $this->assertEquals('user1', $user->getPublicId());
        $this->assertEquals('real_user1_public_id', $user->getUserPublicId());
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
        $access_token->setParameter('token_type', 'bar');
        $access_token->setScope(['bar', 'baz']);
        $this->assertFalse($access_token->hasScope('foo'));
        $this->assertTrue($access_token->hasScope('bar'));
        $this->assertEquals('bar', $access_token->getTokenTypeParameter('token_type'));

        $this->assertEquals([
            'access_token' => 'foo',
            'token_type'   => 'bar',
            'scope'        => 'bar baz',
        ], $access_token->toArray());

        $this->assertFalse($access_token->hasExpired());

        $access_token->setMetadata('foo', 'bar');
        $this->assertTrue($access_token->hasMetadata('foo'));
        $this->assertEquals('bar', $access_token->getMetadata('foo'));
        $access_token->unsetMetadata('foo');
        $this->assertFalse($access_token->hasMetadata('foo'));
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
