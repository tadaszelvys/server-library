<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\ClientInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\RefreshTokenManager as Base;

class RefreshTokenManager extends Base implements RefreshTokenManagerInterface
{
    /**
     * @var \OAuth2\Test\Stub\RefreshToken[]
     */
    private $refresh_tokens = array();

    public function __construct()
    {
        $scope1 = new Scope();
        $scope1->setName('scope1');
        $scope2 = new Scope();
        $scope2->setName('scope2');
        $scope3 = new Scope();
        $scope3->setName('scope3');

        $bar = new PasswordClient();
        $bar->setPublicId('bar')
            ->setSecret('secret')
            ->setAllowedGrantTypes(array('client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code'))
            ->setRedirectUris(array('http://example.com/test?good=false'))
        ;

        $foo = new PublicClient();
        $foo->setPublicId('foo')
            ->setAllowedGrantTypes(array('client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code'))
            ->setRedirectUris(array('http://example.com/test?good=false', 'https://another.uri/callback'))
        ;

        $this->addRefreshToken(
            'VALID_REFRESH_TOKEN',
            time() + 10000,
            $bar,
            array($scope1, $scope2, $scope3)
        );
        $this->addRefreshToken(
            'EXPIRED_REFRESH_TOKEN',
            time() - 1,
            $foo,
            array($scope1, $scope2, $scope3)
        );

        $this->addRefreshToken(
            'REFRESH_EFGH',
            time() + 36000,
            $foo,
            array()
        );
    }

    public function getRefreshTokens()
    {
        return array_keys($this->refresh_tokens);
    }

    protected function addRefreshToken($token, $expiresAt, ClientInterface $client, array $scope = array(), ResourceOwnerInterface $resourceOwner = null)
    {
        $refresh_token = new RefreshToken();
        $refresh_token->setExipresAt($expiresAt)
                      ->setToken($token)
                      ->setClientPublicId($client->getPublicId())
                      ->setResourceOwnerPublicId(is_null($resourceOwner) ? null : $resourceOwner->getPublicId())
                      ->setScope($scope)
                      ->setUsed(false);

        $this->refresh_tokens[$refresh_token->getToken()] = $refresh_token;

        return $refresh_token;
    }

    public function getRefreshToken($token)
    {
        return isset($this->refresh_tokens[$token]) ? $this->refresh_tokens[$token] : null;
    }

    public function markRefreshTokenAsUsed(RefreshTokenInterface $token)
    {
        if (isset($this->refresh_tokens[$token->getToken()])) {
            $token->setUsed(true);
            $this->refresh_tokens[$token->getToken()] = $token;
        }
    }

    public function revokeRefreshToken(RefreshTokenInterface $refresh_token)
    {
        if (isset($this->refresh_tokens[$refresh_token->getToken()])) {
            unset($this->refresh_tokens[$refresh_token->getToken()]);
        }

        return $this;
    }
}
