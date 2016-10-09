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

use OAuth2\Util\Uri;

/**
 * @group Uri
 */
class UriTest extends \PHPUnit_Framework_TestCase
{
    public function testNoStoredUri()
    {
        $this->assertFalse(Uri::isRedirectUriAllowed('http://foo.com', []));
    }

    public function testNotAnUri()
    {
        $this->assertFalse(Uri::isRedirectUriAllowed('not an uri', ['https://www.example.com']));
    }

    public function testPathTraversalNotAllowed()
    {
        $this->assertFalse(Uri::isRedirectUriAllowed('https://www.example.com/../foo', ['https://www.example.com']));
    }

    public function testUriAllowed()
    {
        $this->assertTrue(Uri::isRedirectUriAllowed('https://www.example.com/sub', ['https://www.example.com']));
    }
}
