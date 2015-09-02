<?php

namespace OAuth2\Test;

use OAuth2\Client\PublicClient;

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
        $client->setAllowedGrantTypes(['foo', 'bar']);
        
        $this->assertEquals('public_client', $client->getType());
        $this->assertEquals(['foo', 'bar'], $client->getAllowedGrantTypes());
        $this->assertTrue($client->isAllowedGrantType('foo'));
        $this->assertFalse($client->isAllowedGrantType('baz'));
    }
}
