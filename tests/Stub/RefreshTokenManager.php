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
use OAuth2\ResourceOwner\ResourceOwnerInterface;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\RefreshTokenManager as Base;
use OAuth2\Token\RefreshTokenManagerInterface;

class RefreshTokenManager extends Base implements RefreshTokenManagerInterface
{
    /**
     * @var \OAuth2\Token\RefreshToken[]
     */
    private $refresh_tokens = [];

    /**
     * ClientCredentialsGrantType constructor.
     */
    public function __construct()
    {
        $bar = new Client();
        $bar->set('secret', 'Circle Of Life');
        $bar->set('redirect_uris', ['http://example.com/test?good=false']);
        $bar->set('grant_types', ['client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code']);
        $bar->setPublicId('Mufasa');

        $foo = new Client();
        $foo->set('redirect_uris', ['http://example.com/test?good=false', 'https://another.uri/callback']);
        $foo->set('grant_types', ['client_credentials', 'password', 'token', 'refresh_token', 'code', 'authorization_code']);
        $foo->setPublicId('foo');

        $this->addRefreshToken(
            'VALID_REFRESH_TOKEN',
            time() + 10000,
            $bar,
            $bar,
            ['scope1', 'scope2', 'scope3']
        );
        $this->addRefreshToken(
            'EXPIRED_REFRESH_TOKEN',
            time() - 1,
            $foo,
            $foo,
            ['scope1', 'scope2', 'scope3']
        );

        $this->addRefreshToken(
            'REFRESH_EFGH',
            time() + 36000,
            $foo,
            $foo,
            []
        );
    }

    public function getRefreshTokens()
    {
        return array_keys($this->refresh_tokens);
    }

    protected function addRefreshToken($token, $expiresAt, ClientInterface $client, ResourceOwnerInterface $resourceOwner, array $scope = [])
    {
        $refresh_token = $this->createEmptyRefreshToken();
        $refresh_token->setExpiresAt($expiresAt);
        $refresh_token->setToken($token);
        $refresh_token->setClientPublicId($client->getPublicId());
        $refresh_token->setResourceOwnerPublicId(null === $resourceOwner ? null : $resourceOwner->getPublicId());
        $refresh_token->setScope($scope);

        $this->saveRefreshToken($refresh_token);
    }

    public function getRefreshToken($token)
    {
        return isset($this->refresh_tokens[$token]) ? $this->refresh_tokens[$token] : null;
    }

    public function revokeRefreshToken(RefreshTokenInterface $refresh_token)
    {
        if (isset($this->refresh_tokens[$refresh_token->getToken()])) {
            unset($this->refresh_tokens[$refresh_token->getToken()]);
        }

        return $this;
    }

    protected function saveRefreshToken(RefreshTokenInterface $refresh_token)
    {
        $this->refresh_tokens[$refresh_token->getToken()] = $refresh_token;
    }
}
