<?php

namespace OAuth2\Test\Unit;

use OAuth2\Test\Base;

/**
 * @group AuthorizationFactory
 */
class AuthorizationFactoryTest extends Base
{
    public function testCreateValidAuthorization()
    {
        $params = [
            'client_id' => 'foo',
            'state' => '0123456789',
            'scope' => 'scope1 scope2',
            'response_type' => 'token',
            'display' => 'page',
            'prompt' => 'none',
        ];
        $request = $this->createRequest('/?'.http_build_query($params));
        $authorization = $this->getAuthorizationFactory()->createFromRequest($request);

        $this->assertEquals('0123456789', $authorization->getState());
        $this->assertEquals('foo', $authorization->getClientId());
        $this->assertEquals('foo', $authorization->getClient()->getPublicId());
        $this->assertEquals('token', $authorization->getResponseType());
        $this->assertEquals('page', $authorization->getDisplay());
        $this->assertEquals('none', $authorization->getPrompt());
        $this->assertEquals(['scope1', 'scope2'], $authorization->getScope());
        $this->assertEquals($params, $authorization->getQueryParams());
    }
}
