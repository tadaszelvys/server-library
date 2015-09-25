<?php

namespace OAuth2\Test;

use OAuth2\Endpoint\Authorization;
use OAuth2\Exception\BaseExceptionInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\Uri;

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
                      ->setResponseType('code token')
                      ->setAuthorized(true);

        $response = new Response();
        $this->getAuthorizationEndpoint()->authorize($authorization, $response);
        $this->assertRegExp('/^http:\/\/example.com\/test\?good=false#code=[^"]+&access_token=[^"]+&expires_in=3600&scope=scope1\+scope2&token_type=Bearer$/', $response->getHeader('Location')[0]);
    }
}
