<?php

namespace OAuth2\Test\Unit;

use OAuth2\Client\PublicClient;
use OAuth2\Test\Base;

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
}
