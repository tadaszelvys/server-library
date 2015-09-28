<?php

namespace OAuth2\Test\Functional;

use OAuth2\Exception\InternalServerErrorException;
use OAuth2\Test\Base;

/**
 * @group BearerToken
 */
class BearerTokenTest extends Base
{
    public function testAccessTokenFromQuery()
    {
        $request = $this->createRequest('/foo?access_token=ABCD');
        $access_token = $this->getAccessTokenTypeManager()->findAccessToken($request, $type);

        $this->assertEquals('ABCD', $access_token);
        $this->assertInstanceOf('\OAuth2\Token\BearerAccessToken', $type);
    }

    public function testAccessTokenFromHeader()
    {
        $request = $this->createRequest('/', 'GET', [], [], ['Authorization' => 'Bearer ABCD']);
        $access_token = $this->getAccessTokenTypeManager()->findAccessToken($request, $type);

        $this->assertEquals('ABCD', $access_token);
        $this->assertInstanceOf('\OAuth2\Token\BearerAccessToken', $type);
    }

    public function testAccessTokenFromRequestBody()
    {
        $request = $this->createRequest('/', 'POST', [], [], [], http_build_query(['foo' => 'bar', 'access_token' => 'ABCD']));
        $access_token = $this->getAccessTokenTypeManager()->findAccessToken($request, $type);

        $this->assertEquals('ABCD', $access_token);
        $this->assertInstanceOf('\OAuth2\Token\BearerAccessToken', $type);
    }

    public function testInvalidAccessToken()
    {
        $request = $this->createRequest('/', 'GET', [], [], ['Authorization' => 'MAC ABCD']);
        $access_token = $this->getAccessTokenTypeManager()->findAccessToken($request, $type);

        $this->assertNull($access_token);
    }

    public function testAccessTokenTypeAlreadyAdded()
    {
        try {
            $this->getAccessTokenTypeManager()->addAccessTokenType($this->getBearerAccessTokenType());
            $this->fail('Should throw an Exception');
        } catch (InternalServerErrorException $e) {
            $this->assertEquals('server_error', $e->getMessage());
            $this->assertEquals('Scheme "Bearer" already defined.', $e->getDescription());
        }
    }
}
