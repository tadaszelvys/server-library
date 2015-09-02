<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\ClientInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
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
        $valid_auth_code->setClientPublicId('bar')
                  ->setIssueRefreshToken(true)
                  ->setRedirectUri('http://example.com/redirect_uri/')
                  ->setResourceOwnerPublicId(null)
                  ->setExpiresAt(time() + 3000)
                  ->setScope([
                      'scope1',
                      'scope2',
                  ])
                  ->setToken('VALID_AUTH_CODE');

        $expired_auth_code = new AuthCode();
        $expired_auth_code->setClientPublicId('bar')
                  ->setIssueRefreshToken(true)
                  ->setRedirectUri('http://example.com/redirect_uri/')
                  ->setResourceOwnerPublicId(null)
                  ->setExpiresAt(time() - 1)
                  ->setScope([
                      'scope1',
                      'scope2',
                  ])
                  ->setToken('VALID_AUTH_CODE');

        $this->auth_codes['VALID_AUTH_CODE'] = $valid_auth_code;
        $this->auth_codes['EXPIRED_AUTH_CODE'] = $expired_auth_code;
    }

    protected function getGenerator()
    {
        return new DefuseGenerator();
    }

    protected function addAuthCode($code, $expiresAt, ClientInterface $client, $redirectUri, array $scope = [], ResourceOwnerInterface $resourceOwner = null, $issueRefreshToken = false)
    {
        $auth_code = new AuthCode();
        $auth_code->setExpiresAt($expiresAt)
                  ->setClientPublicId($client->getPublicId())
                  ->setIssueRefreshToken($issueRefreshToken)
                  ->setRedirectUri($redirectUri)
                  ->setResourceOwnerPublicId(is_null($resourceOwner) ? null : $resourceOwner->getPublicId())
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
