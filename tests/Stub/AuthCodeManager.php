<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Client\ClientInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\Token\AuthCode;
use OAuth2\Token\AuthCodeInterface;
use OAuth2\Token\AuthCodeManager as Base;
use Security\DefuseGenerator;

class AuthCodeManager extends Base
{
    private $auth_codes = [];

    public function __construct()
    {
        $valid_auth_code1 = new AuthCode();
        $valid_auth_code1->setIssueRefreshToken(true)
            ->setRedirectUri('http://example.com/redirect_uri/')
            ->setClientPublicId('bar')
            ->setResourceOwnerPublicId('user1')
            ->setExpiresAt(time() + 3000)
            ->setScope([
                'scope1',
                'scope2',
            ])
            ->setToken('VALID_AUTH_CODE');

        $valid_auth_code2 = new AuthCode();
        $valid_auth_code2->setIssueRefreshToken(true)
            ->setRedirectUri('http://example.com/redirect_uri/')
            ->setClientPublicId('foo')
            ->setResourceOwnerPublicId('user1')
            ->setExpiresAt(time() + 3000)
            ->setScope([
                'scope1',
                'scope2',
            ])
            ->setToken('VALID_AUTH_CODE_PUBLIC_CLIENT');

        $expired_auth_code = new AuthCode();
        $expired_auth_code->setIssueRefreshToken(true)
            ->setRedirectUri('http://example.com/redirect_uri/')
            ->setClientPublicId('bar')
            ->setResourceOwnerPublicId('user1')
            ->setExpiresAt(time() - 1)
            ->setScope([
                'scope1',
                'scope2',
            ])
            ->setToken('EXPIRED_AUTH_CODE');

        $this->auth_codes['VALID_AUTH_CODE'] = $valid_auth_code1;
        $this->auth_codes['VALID_AUTH_CODE_PUBLIC_CLIENT'] = $valid_auth_code2;
        $this->auth_codes['EXPIRED_AUTH_CODE'] = $expired_auth_code;
    }

    protected function getGenerator()
    {
        return new DefuseGenerator();
    }

    protected function addAuthCode($code, $expiresAt, ClientInterface $client, EndUserInterface $end_user, array $query_params, $redirectUri, array $scope = [], $issueRefreshToken = false)
    {
        $auth_code = new AuthCode();
        $auth_code->setIssueRefreshToken($issueRefreshToken)
            ->setQueryParams($query_params)
            ->setRedirectUri($redirectUri)
            ->setClientPublicId($client->getPublicId())
            ->setExpiresAt($expiresAt)
            ->setResourceOwnerPublicId($end_user->getPublicId())
            ->setScope($scope)
            ->setToken($code);

        $this->auth_codes[$code] = $auth_code;

        return $auth_code;
    }

    public function getAuthCode($code)
    {
        if (isset($this->auth_codes[$code])) {
            return $this->auth_codes[$code];
        }
    }

    public function markAuthCodeAsUsed(AuthCodeInterface $code)
    {
        if (isset($this->auth_codes[$code->getToken()])) {
            unset($this->auth_codes[$code->getToken()]);
        }
    }
}
