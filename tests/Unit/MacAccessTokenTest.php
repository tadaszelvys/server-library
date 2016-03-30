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

use OAuth2\Test\Base;

/**
 * @group MAC
 */
class MacAccessTokenTest extends Base
{
    public function testValidMacRequest()
    {
        $access_token = $this->getJWTAccessTokenManager()->getAccessToken('USER_INFO_MAC');

        $request = $this->createMacRequest(
            $access_token->getToken(),
            'sha256',
            $access_token->getParameter('mac_key')
        );

        $values = [];
        $token = $this->getMacTokenType()->findToken($request, $values);
        $is_valid = $this->getMacTokenType()->isTokenRequestValid($access_token, $request, $values);

        $this->assertEquals($token, $access_token->getToken());
        $this->assertTrue($is_valid);
    }

    public function testTimestampIsTooOld()
    {
        $access_token = $this->getJWTAccessTokenManager()->getAccessToken('USER_INFO_MAC');

        $request = $this->createMacRequest(
            $access_token->getToken(),
            'sha256',
            $access_token->getParameter('mac_key'),
            time() - 1000
        );

        $values = [];
        $this->getMacTokenType()->findToken($request, $values);
        $is_valid = $this->getMacTokenType()->isTokenRequestValid($access_token, $request, $values);
        $this->assertFalse($is_valid);
    }

    public function testInvalidSignatureFromWrongAlgorithm()
    {
        $access_token = $this->getJWTAccessTokenManager()->getAccessToken('USER_INFO_MAC');

        $request = $this->createMacRequest(
            $access_token->getToken(),
            'sha1',
            $access_token->getParameter('mac_key')
        );

        $values = [];
        $this->getMacTokenType()->findToken($request, $values);
        $is_valid = $this->getMacTokenType()->isTokenRequestValid($access_token, $request, $values);
        $this->assertFalse($is_valid);
    }

    public function testInvalidSignatureFromWrongKey()
    {
        $access_token = $this->getJWTAccessTokenManager()->getAccessToken('USER_INFO_MAC');

        $request = $this->createMacRequest(
            $access_token->getToken(),
            'sha256',
            'Wrong Key'
        );

        $values = [];
        $this->getMacTokenType()->findToken($request, $values);
        $is_valid = $this->getMacTokenType()->isTokenRequestValid($access_token, $request, $values);
        $this->assertFalse($is_valid);
    }

    /**
     * @param string      $mac_id
     * @param string      $mac_algorithm
     * @param string      $mac_key
     * @param null|int    $timestamp
     * @param string      $uri
     * @param string      $method
     * @param array       $parameters
     * @param array       $server
     * @param array       $headers
     * @param null|string $content
     *
     * @return \Psr\Http\Message\ServerRequestInterface
     */
    private function createMacRequest($mac_id, $mac_algorithm, $mac_key, $timestamp = null, $uri = '/', $method = 'GET', array $parameters = [], array $server = [], array $headers = [], $content = null)
    {
        if (null === $timestamp) {
            $timestamp = time();
        }

        $header = $this->generateHeader($mac_id, $mac_algorithm, $mac_key, $timestamp, $method, $uri);

        $request = $this->createRequest($uri, $method, $parameters, $server, array_merge($headers, ['Authorization' => $header]), $content);
        return $request;
    }

    private function generateHeader($mac_id, $mac_algorithm, $mac_key, $timestamp, $method, $request_uri, $ext = null)
    {
        $nonce = uniqid('----');
        $mac = $this->generateMac($mac_algorithm, $mac_key, $timestamp, $nonce, $method, $request_uri, $ext);
        $data = [
            sprintf('id="%s"', $mac_id),
            sprintf('ts="%s"', $timestamp),
            sprintf('nonce="%s"', $nonce),
            sprintf('mac="%s"', $mac),
        ];
        if (null !== $ext) {
            $data[] = sprintf('ext="%s"', $ext);
        }

        return sprintf('MAC %s', implode(',', $data));
    }

    private function generateMac($mac_algorithm, $mac_key, $timestamp, $nonce, $method, $request_uri, $ext = null)
    {
        $basestr =
            $timestamp."\n".
            $nonce."\n".
            $method."\n".
            $request_uri."\n".
            'localhost'."\n".
            "\n".
            $ext."\n";

        return base64_encode(hash_hmac(
            $mac_algorithm,
            $basestr,
            $mac_key,
            true
        ));
    }
}
