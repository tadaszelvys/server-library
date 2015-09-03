<?php

namespace OAuth2\Test;

use OAuth2\Client\PublicClient;
use OAuth2\Exception\ExceptionManagerInterface;

/**
 * @group Objects
 */
class ExceptionManagerTest extends Base
{
    public function testInternalServerError()
    {
        $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::INTERNAL_SERVER_ERROR, 'foo', 'bar');

        $this->assertEquals('bar', $exception->getDescription());
        $this->assertEquals(500, $exception->getHttpCode());
        $this->assertEquals('{"error":"foo","error_description":"bar","error_uri":"https%3A%2F%2Ffoo.test%2FInternal%2FInternalServerError%2Ffoo"}', $exception->getResponseBody());
        $this->assertEquals('https://foo.test/Internal/InternalServerError/foo', $exception->getUri());
    }

    public function testRedirectButRedirectUriNotDefined()
    {
        try {
            $this->getExceptionManager()->getException(ExceptionManagerInterface::REDIRECT, 'foo', 'bar');
        } catch(\InvalidArgumentException $e) {
            $this->assertEquals('redirect_uri_not_defined', $e->getMessage());
        }
    }

    public function testRedirectButTransportModeNotDefined()
    {
        try {
            $this->getExceptionManager()->getException(ExceptionManagerInterface::REDIRECT, 'foo', 'bar', ['redirect_uri' => 'https://foo.bar']);
        } catch(\InvalidArgumentException $e) {
            $this->assertEquals('invalid_transport_mode', $e->getMessage());
        }
    }

    public function testRedirectButRedirect()
    {
        $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::REDIRECT, 'foo', 'bar', ['redirect_uri' => 'https://foo.bar', 'transport_mode' => 'query']);

        $this->assertEquals('bar', $exception->getDescription());
        $this->assertEquals(302, $exception->getHttpCode());
        $this->assertEquals(
            [
                'Location' => 'https://foo.bar?error=foo&error_description=bar&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Ffoo'
            ],
            $exception->getResponseHeaders());
    }
}
