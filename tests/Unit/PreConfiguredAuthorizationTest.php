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

use OAuth2\Endpoint\Authorization\PreConfiguredAuthorization\PreConfiguredAuthorization;

/**
 * @group PreConfiguredAuthorization
 */
class PreConfiguredAuthorizationTest extends \PHPUnit_Framework_TestCase
{
    public function testObject()
    {
        $pca = new PreConfiguredAuthorization();
        $pca->setClientPublicId('foo');
        $pca->setResourceOwnerPublicId('bar');
        $pca->setUserAccountPublicId('baz');
        $pca->setRequestedScopes(['scope']);
        $pca->setValidatedScopes([]);

        $this->assertEquals('foo', $pca->getClientPublicId());
        $this->assertEquals('bar', $pca->getResourceOwnerPublicId());
        $this->assertEquals('baz', $pca->getUserAccountPublicId());
        $this->assertEquals(['scope'], $pca->getRequestedScopes());
        $this->assertEquals([], $pca->getValidatedScopes());
    }
}
