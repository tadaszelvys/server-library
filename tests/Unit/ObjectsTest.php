<?php

namespace OAuth2\Test\Unit;

use OAuth2\Client\PublicClient;
use OAuth2\Endpoint\Authorization;
use OAuth2\Exception\AuthenticateException;
use OAuth2\Test\Base;
use OAuth2\Test\Stub\EndUser;
use OAuth2\Token\AuthCode;

/**
 * @group Objects
 */
class ObjectsTest extends Base
{
    public function testConfiguration()
    {
        $this->assertNull($this->getConfiguration()->get('foo'));

        $this->assertEquals('bar', $this->getConfiguration()->get('foo', 'bar'));

        $this->getConfiguration()->set('foo', 'baz');
        $this->assertEquals('baz', $this->getConfiguration()->get('foo'));

        $this->getConfiguration()->delete('foo');
        $this->assertNull($this->getConfiguration()->get('foo'));
    }

    public function testClient()
    {
        $client = new PublicClient();
        $client->setAllowedGrantTypes(['foo', 'bar'])
            ->addAllowedGrantType('baz')
            ->removeAllowedGrantType('baz')
            ->setRedirectUris(['https://foo.com'])
            ->addRedirectUri('https://baz.com')
            ->removeRedirectUri('https://baz.com');

        $this->assertEquals('public_client', $client->getType());
        $this->assertEquals(['foo', 'bar'], $client->getAllowedGrantTypes());
        $this->assertEquals(['https://foo.com'], $client->getRedirectUris());
        $this->assertTrue($client->hasRedirectUri('https://foo.com'));
        $this->assertFalse($client->hasRedirectUri('https://bar.com'));
        $this->assertTrue($client->isAllowedGrantType('foo'));
        $this->assertFalse($client->isAllowedGrantType('baz'));
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

    public function testAuthenticateException()
    {
        $exception = new AuthenticateException('foo_error', 'foo_description', 'https://foo.com/error', ['schemes' => ['Bearer' => []]]);

        $this->assertNull($exception->getResponseBody());
        $this->assertEquals([
            'Content-Type'     => 'application/json',
            'Cache-Control'    => 'no-store',
            'Pragma'           => 'no-cache',
            'WWW-Authenticate' => [
                'Bearer',
            ],
        ], $exception->getResponseHeaders());
    }

    /**
     * @expectedException \BadMethodCallException
     * @expectedExceptionMessage Unknown method "getFooBar"
     */
    public function testAuthorizationBadMethodCall()
    {
        $authorization = new Authorization();
        $authorization->getFooBar();
    }
}
