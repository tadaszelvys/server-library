<?php

namespace OAuth2\Test;
use Zend\Diactoros\ServerRequest;

/**
 * @group BearerToken
 */
class BearerTokenTest extends Base
{
    public function testAccessTokenFromQuery()
    {
        $request = $this->createRequest('/foo?access_token=ABCD');
        $access_token = $this->getAccessTokenType()->findAccessToken($request);

        $this->assertEquals('ABCD', $access_token);
    }

    public function testAccessTokenFromHeader()
    {
        $request = $this->createRequest('/', 'GET', [], [], ['Authorization' => 'Bearer ABCD']);
        $access_token = $this->getAccessTokenType()->findAccessToken($request);

        $this->assertEquals('ABCD', $access_token);
    }

    public function testAccessTokenFromRequestBody()
    {
        $request = $this->createRequest('/', 'POST', [], [], [], http_build_query(['foo' => 'bar', 'access_token'=> 'ABCD']));
        $access_token = $this->getAccessTokenType()->findAccessToken($request);

        $this->assertEquals('ABCD', $access_token);
    }
}
