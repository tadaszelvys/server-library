<?php

namespace OAuth2\Test\Functional;

use OAuth2\Endpoint\Authorization;
use OAuth2\Test\Base;
use Zend\Diactoros\Response;

/**
 * @group OpenIDConnect
 */
class OpenIDConnectTest extends Base
{
    public function testCodeTokenSuccess()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
            ->setClient($client)
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
            ->setResponseType('code token')
            ->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&access_token=[^"]+&expires_in=3600&scope=scope1\+scope2&token_type=Bearer$/', $response->getHeader('Location')[0]);
    }

    public function testCodeIdTokenTokenSuccess()
    {
        $this->markTestIncomplete('ID Token not yet implemented');

        return;

        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
            ->setClient($client)
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
            ->setResponseType('code id_token token')
            ->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);

        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&id_token=[^"]+&access_token=[^"]+&expires_in=3600&scope=scope1\+scope2&token_type=Bearer$/', $response->getHeader('Location')[0]);
    }

    public function testNoneSuccess()
    {
        $client = $this->getClientManagerSupervisor()->getClient('foo');
        if (null === $client) {
            $this->fail('Unable to get client');

            return;
        }
        $authorization = new Authorization();
        $authorization->setRedirectUri('http://example.com/test?good=false')
            ->setClient($client)
            ->setEndUser($this->getEndUserManager()->getEndUser('user1'))
            ->setResponseType('none')
            ->setState('0123456789')
            ->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);

        $this->assertEquals('http://example.com/test?good=false&state=0123456789', $response->getHeader('Location')[0]);
    }
}
