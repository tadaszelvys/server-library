<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Client\ClientInterface;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\EndUser\EndUserInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Token\AuthCode;
use OAuth2\Token\AuthCodeInterface;
use OAuth2\Token\AuthCodeManager as Base;
use Security\DefuseGenerator;

class AuthCodeManager extends Base
{
    private $auth_codes = [];

    /**
     * AuthCodeManager constructor.
     *
     * @param \OAuth2\Exception\ExceptionManagerInterface  $exception_manager
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     */
    public function __construct(ExceptionManagerInterface $exception_manager, ConfigurationInterface $configuration)
    {
        parent::__construct($exception_manager, $configuration);

        $valid_auth_code1 = new AuthCode();
        $valid_auth_code1->setIssueRefreshToken(true);
        $valid_auth_code1->setRedirectUri('http://example.com/redirect_uri/');
        $valid_auth_code1->setClientPublicId('bar');
        $valid_auth_code1->setResourceOwnerPublicId('user1');
        $valid_auth_code1->setExpiresAt(time() + 3000);
        $valid_auth_code1->setScope([
                'scope1',
                'scope2',
            ]);
        $valid_auth_code1->setToken('VALID_AUTH_CODE');

        $valid_auth_code2 = new AuthCode();
        $valid_auth_code2->setIssueRefreshToken(true);
        $valid_auth_code2->setRedirectUri('http://example.com/redirect_uri/');
        $valid_auth_code2->setClientPublicId('foo');
        $valid_auth_code2->setResourceOwnerPublicId('user1');
        $valid_auth_code2->setExpiresAt(time() + 3000);
        $valid_auth_code2->setScope([
                'scope1',
                'scope2',
            ]);
        $valid_auth_code2->setQueryParams([
            'code_challenge'        => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'plain',
        ]);
        $valid_auth_code2->setToken('VALID_AUTH_CODE_PUBLIC_CLIENT');

        $expired_auth_code = new AuthCode();
        $expired_auth_code->setIssueRefreshToken(true);
        $expired_auth_code->setRedirectUri('http://example.com/redirect_uri/');
        $expired_auth_code->setClientPublicId('bar');
        $expired_auth_code->setResourceOwnerPublicId('user1');
        $expired_auth_code->setExpiresAt(time() - 1);
        $expired_auth_code->setScope([
                'scope1',
                'scope2',
            ]);
        $expired_auth_code->setToken('EXPIRED_AUTH_CODE');

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
        $auth_code->setIssueRefreshToken($issueRefreshToken);
        $auth_code->setQueryParams($query_params);
        $auth_code->setRedirectUri($redirectUri);
        $auth_code->setClientPublicId($client->getPublicId());
        $auth_code->setExpiresAt($expiresAt);
        $auth_code->setResourceOwnerPublicId($end_user->getPublicId());
        $auth_code->setScope($scope);
        $auth_code->setToken($code);

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
