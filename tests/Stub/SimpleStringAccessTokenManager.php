<?php

namespace OAuth2\Test\Stub;

use OAuth2\Client\ClientInterface;
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\SimpleStringAccessTokenManager as Base;

class SimpleStringAccessTokenManager extends Base
{
    /**
     * @var \OAuth2\Token\AccessTokenInterface[]
     */
    private $access_tokens = [];

    public function __construct()
    {
        $abcd = new SimpleStringAccessToken();
        $abcd->setExipresAt(time() + 3600)
             ->setResourceOwnerPublicId(null)
             ->setScope([])
             ->setClientPublicId('bar')
             ->setRefreshToken(null)
             ->setToken('ABCD');

        $efgh = new SimpleStringAccessToken();
        $efgh->setExipresAt(time() + 3600)
             ->setResourceOwnerPublicId(null)
             ->setScope([])
             ->setClientPublicId('foo')
             ->setRefreshToken('REFRESH_EFGH')
             ->setToken('EFGH');

        $this->access_tokens['ABCD'] = $abcd;
        $this->access_tokens['EFGH'] = $efgh;
    }
    /**
     * {@inheritdoc}
     */
    protected function addAccessToken($token, $expiresAt, ClientInterface $client, array $scope = [], ResourceOwnerInterface $resourceOwner = null, RefreshTokenInterface $refresh_token = null)
    {
        $access_token = new SimpleStringAccessToken();
        $access_token->setExipresAt($expiresAt)
                     ->setScope($scope)
                     ->setResourceOwnerPublicId(is_null($resourceOwner) ? null : $resourceOwner->getPublicId())
                     ->setClientPublicId($client->getPublicId())
                     ->setRefreshToken(is_null($refresh_token) ? null : $refresh_token->getToken())
                     ->setToken($token);

        $this->access_tokens[$access_token->getToken()] = $access_token;

        return $access_token;
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken(AccessTokenInterface $access_token)
    {
        if (isset($this->access_tokens[$access_token->getToken()])) {
            unset($this->access_tokens[$access_token->getToken()]);
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($token)
    {
        return isset($this->access_tokens[$token]) ? $this->access_tokens[$token] : null;
    }
}
