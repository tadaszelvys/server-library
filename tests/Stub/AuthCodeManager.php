<?php

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
        $valid_auth_code = new AuthCode();
        $valid_auth_code->setIssueRefreshToken(true)
            ->setRedirectUri('http://example.com/redirect_uri/')
            ->setClientPublicId('bar')
            ->setResourceOwnerPublicId('user1')
            ->setExpiresAt(time() + 3000)
            ->setScope([
                'scope1',
                'scope2',
            ])
            ->setToken('VALID_AUTH_CODE');

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

        $this->auth_codes['VALID_AUTH_CODE'] = $valid_auth_code;
        $this->auth_codes['EXPIRED_AUTH_CODE'] = $expired_auth_code;
    }

    protected function getGenerator()
    {
        return new DefuseGenerator();
    }

    protected function addAuthCode($code, $expiresAt, ClientInterface $client, EndUserInterface $end_user, $redirectUri, array $scope = [], $issueRefreshToken = false)
    {
        $auth_code = new AuthCode();
        $auth_code->setIssueRefreshToken($issueRefreshToken)
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
