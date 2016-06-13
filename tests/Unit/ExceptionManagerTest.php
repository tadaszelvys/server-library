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
use OAuth2\ResponseMode\FormPostResponseMode;
use OAuth2\ResponseMode\FragmentResponseMode;
use OAuth2\ResponseMode\QueryResponseMode;
use OAuth2\Test\Base;
use PHPHtmlParser\Dom;
use Zend\Diactoros\Response;

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
            $this->assertEquals('invalid_response_mode', $e->getMessage());
        }
    }

    public function testRedirectExceptionWithQueryResponseMode()
    {
        $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::REDIRECT, 'foo', 'bar', ['redirect_uri' => 'https://foo.bar', 'response_mode' => new QueryResponseMode()]);
        $response = new Response();
        $exception->getHttpResponse($response);
        $response->getBody()->rewind();

        $this->assertEquals('', $response->getBody()->getContents());
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals(
            [
                'Location'                => ['https://foo.bar/?error=foo&error_description=bar&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Ffoo#'],
                'Content-Security-Policy' => ['referrer origin;'],
            ],
            $response->getHeaders());
    }

    public function testRedirectExceptionWithFragmentResponseMode()
    {
        $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::REDIRECT, 'foo', 'bar', ['redirect_uri' => 'https://foo.bar', 'response_mode' => new FragmentResponseMode()]);
        $response = new Response();
        $exception->getHttpResponse($response);
        $response->getBody()->rewind();

        $this->assertEquals('', $response->getBody()->getContents());
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals(
            [
                'Location'                => ['https://foo.bar/#error=foo&error_description=bar&error_uri=https%3A%2F%2Ffoo.test%2FError%2FRedirect%2Ffoo'],
                'Content-Security-Policy' => ['referrer origin;'],
            ],
            $response->getHeaders());
    }

    public function testRedirectExceptionWithFormPostResponseMode()
    {
        $exception = $this->getExceptionManager()->getException(ExceptionManagerInterface::REDIRECT, 'foo', 'bar', ['redirect_uri' => 'https://foo.bar', 'response_mode' => new FormPostResponseMode()]);
        $response = new Response();
        $exception->getHttpResponse($response);
        $response->getBody()->rewind();

        $content = $response->getBody()->getContents();
        $dom = new Dom();
        $dom->load($content);
        $inputs = $dom->find('input');

        $this->assertNotNull($inputs);
        $this->assertEquals(3, count($inputs));
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(
            [
                'Content-Security-Policy' => ['referrer origin;'],
            ],
            $response->getHeaders());
    }
}
