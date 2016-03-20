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

use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Test\Base;

/**
 * @group Objects
 */
class ExceptionManagerTest extends Base
{
    public function testRedirectButRedirectUriNotDefined()
    {
        try {
            $this->getExceptionManager()->getException(ExceptionManagerInterface::REDIRECT, 'foo', 'bar');
        } catch (\InvalidArgumentException $e) {
            $this->assertEquals('redirect_uri_not_defined', $e->getMessage());
        }
    }

    public function testRedirectButTransportModeNotDefined()
    {
        try {
            $this->getExceptionManager()->getException(ExceptionManagerInterface::REDIRECT, 'foo', 'bar', ['redirect_uri' => 'https://foo.bar']);
        } catch (\InvalidArgumentException $e) {
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
                'Location'                => 'https://foo.bar/?error=foo&error_description=bar&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Ffoo',
                'Content-Security-Policy' => 'referrer origin;',
            ],
            $exception->getResponseHeaders());
    }
}
