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
use OAuth2\Test\Base;

/**
 * @group AuthorizationFactory
 */
class AuthorizationFactoryTest extends Base
{
    public function testCreateValidAuthorization()
    {
        $params = [
            'client_id'     => 'foo',
            'state'         => '0123456789',
            'scope'         => 'scope1 scope2',
            'response_type' => 'token',
            'display'       => 'page',
            'prompt'        => 'none',
            'redirect_uri'  => 'https://another.uri/callback',
        ];
        $request = $this->createRequest('/?'.http_build_query($params));
        $authorization = $this->getAuthorizationFactory()->createAuthorizationFromRequest($request);
        $authorization->setUser($this->getUserManager()->getUser('user1'));
        $authorization->setAuthorized(true);

        $this->assertEquals('0123456789', $authorization->getQueryParam('state'));
        $this->assertEquals('foo', $authorization->getQueryParam('client_id'));
        $this->assertEquals('foo', $authorization->getClient()->getPublicId());
        $this->assertEquals('token', $authorization->getQueryParam('response_type'));
        $this->assertEquals('page', $authorization->getQueryParam('display'));
        $this->assertEquals(['none'], $authorization->getQueryParam('prompt'));
        $this->assertEquals(['scope1','scope2'], $authorization->getQueryParam('scope'));
    }

    public function testPromptNoneMustBeUsedAlone()
    {
        $params = [
            'client_id'     => 'foo',
            'state'         => '0123456789',
            'scope'         => 'scope1 scope2',
            'response_type' => 'token',
            'display'       => 'page',
            'prompt'        => 'none login',
            'redirect_uri'  => 'https://another.uri/callback',
        ];
        $request = $this->createRequest('/?'.http_build_query($params));

        try {
            $this->getAuthorizationFactory()->createAuthorizationFromRequest($request);
            $this->fail('The expected exception was not thrown');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Invalid parameter "prompt". Prompt value "none" must be used alone.', $e->getDescription());
        }
    }

    public function testCreateAuthorizationWithBadPrompt()
    {
        $params = [
            'client_id'     => 'foo',
            'state'         => '0123456789',
            'scope'         => 'scope1 scope2',
            'response_type' => 'token',
            'display'       => 'page',
            'prompt'        => 'foo',
        ];
        $request = $this->createRequest('/?'.http_build_query($params));

        try {
            $this->getAuthorizationFactory()->createAuthorizationFromRequest($request);
            $this->fail('The expected exception was not thrown');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Invalid parameter "prompt". Allowed values are ["none","login","consent","select_account"]', $e->getDescription());
        }
    }

    public function testCreateAuthorizationWithBadDisplay()
    {
        $params = [
            'client_id' => 'foo',
            'state' => '0123456789',
            'scope' => 'scope1 scope2',
            'response_type' => 'token',
            'display' => 'foo',
            'prompt' => 'none',
            'redirect_uri' => 'https://another.uri/callback',
        ];
        $request = $this->createRequest('/?' . http_build_query($params));
        try {
            $this->getAuthorizationFactory()->createAuthorizationFromRequest($request);
            $this->fail('The expected exception was not thrown');
        } catch (BaseExceptionInterface $e) {
            $this->assertEquals('invalid_request', $e->getMessage());
            $this->assertEquals('Invalid parameter "display". Allowed values are ["page","popup","touch","wap"]', $e->getDescription());
        }
    }
}
