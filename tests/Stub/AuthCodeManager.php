<?php

namespace OAuth2\Test\Stub;

use OAuth2\Token\AuthCode;
use OAuth2\Token\AuthCodeManager as Base;
use OAuth2\Client\ClientInterface;
use Security\DefuseGenerator;
use OAuth2\Token\AuthCodeInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;

class AuthCodeManager extends Base
{
    private $auth_codes = array();

    public function __construct()
    {
        $scope1 = new Scope();
        $scope1->setName('scope1');
        $scope2 = new Scope();
        $scope2->setName('scope2');

        $valid_auth_code = new AuthCode();
        $valid_auth_code->setClientPublicId('bar')
                  ->setIssueRefreshToken(true)
                  ->setRedirectUri('http://example.com/redirect_uri/')
                  ->setResourceOwnerPublicId(null)
                  ->setExipresAt(time() + 3000)
                  ->setScope(array(
                      $scope1,
                      $scope2,
                  ))
                  ->setCode('VALID_AUTH_CODE');

        $expired_auth_code = new AuthCode();
        $expired_auth_code->setClientPublicId('bar')
                  ->setIssueRefreshToken(true)
                  ->setRedirectUri('http://example.com/redirect_uri/')
                  ->setResourceOwnerPublicId(null)
                  ->setExipresAt(time() - 1)
                  ->setScope(array(
                      $scope1,
                      $scope2,
                  ))
                  ->setCode('VALID_AUTH_CODE');

        $this->auth_codes['VALID_AUTH_CODE'] = $valid_auth_code;
        $this->auth_codes['EXPIRED_AUTH_CODE'] = $expired_auth_code;
    }

    protected function getGenerator()
    {
        return new DefuseGenerator();
    }

    protected function addAuthCode($code, $expiresAt, ClientInterface $client, $redirectUri, array $scope = array(), ResourceOwnerInterface $resourceOwner = null, $issueRefreshToken = false)
    {
        $auth_code = new AuthCode();
        $auth_code->setExipresAt($expiresAt)
                  ->setClientPublicId($client->getPublicId())
                  ->setIssueRefreshToken($issueRefreshToken)
                  ->setRedirectUri($redirectUri)
                  ->setResourceOwnerPublicId(is_null($resourceOwner) ? null : $resourceOwner->getPublicId())
                  ->setScope($scope)
                  ->setCode($code);

        $this->auth_codes[$code] = $auth_code;

        return $auth_code;
    }

    public function getAuthCode($code)
    {
        if (isset($this->auth_codes[$code])) {
            return $this->auth_codes[$code];
        }

        return;
    }

    public function markAuthCodeAsUsed(AuthCodeInterface $code)
    {
        if (isset($this->auth_codes[$code->getCode()])) {
            unset($this->auth_codes[$code->getCode()]);
        }
    }
}
