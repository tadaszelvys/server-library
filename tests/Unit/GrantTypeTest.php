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

use OAuth2\Exception\BaseExceptionInterface;
use OAuth2\Grant\AuthorizationCodeGrantType;
use OAuth2\Test\Base;

/**
 * @group GrantType
 */
class GrantTypeTest extends Base
{
    public function testAssociatedGrantType()
    {
        $this->assertEquals(['authorization_code'], $this->getAuthorizationCodeGrantType()->getAssociatedGrantTypes());
        $this->assertEquals(['code'], $this->getAuthorizationCodeGrantType()->getAssociatedResponseTypes());
        $this->assertEquals([], $this->getImplicitGrantType()->getAssociatedGrantTypes());
        $this->assertEquals([], $this->getResourceOwnerPasswordCredentialsGrantType()->getAssociatedResponseTypes());
        $this->assertEquals([], $this->getClientCredentialsGrantType()->getAssociatedResponseTypes());
        $this->assertEquals([], $this->getRefreshTokenGrantType()->getAssociatedResponseTypes());
        $this->assertEquals([], $this->getNoneResponseType()->getAssociatedGrantTypes());
        $this->assertEquals([], $this->getIdTokenGrantType()->getAssociatedGrantTypes());
    }
}
