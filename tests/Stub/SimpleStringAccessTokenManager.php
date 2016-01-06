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

use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\Token\AccessToken;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\AccessTokenTypeManagerInterface;
use OAuth2\Token\SimpleStringAccessTokenManager as Base;

class SimpleStringAccessTokenManager extends Base
{
    /**
     * @var \OAuth2\Token\AccessTokenInterface[]
     */
    private $access_tokens = [];

    /**
     * SimpleStringAccessTokenManager constructor.
     *
     * @param \OAuth2\Configuration\ConfigurationInterface  $configuration
     * @param \OAuth2\Token\AccessTokenTypeManagerInterface $access_token_type_manager
     */
    public function __construct(ConfigurationInterface $configuration, AccessTokenTypeManagerInterface $access_token_type_manager)
    {
        parent::__construct($configuration, $access_token_type_manager);

        $abcd = new AccessToken();
        $abcd->setExpiresAt(time() + 3600);
        $abcd->setResourceOwnerPublicId('bar');
        $abcd->setScope([]);
        $abcd->setClientPublicId('bar');
        $abcd->setRefreshToken(null);
        $abcd->setToken('ABCD');
        $abcd->setTokenType('Bearer');

        $efgh = new AccessToken();
        $efgh->setExpiresAt(time() + 3600);
        $efgh->setResourceOwnerPublicId('foo');
        $efgh->setScope([]);
        $efgh->setClientPublicId('foo');
        $efgh->setRefreshToken('REFRESH_EFGH');
        $efgh->setToken('EFGH');
        $efgh->setTokenType('Bearer');

        $this->saveAccessToken($abcd);
        $this->saveAccessToken($efgh);
    }

    /**
     * {@inheritdoc}
     */
    protected function saveAccessToken(AccessTokenInterface $access_token)
    {
        $this->access_tokens[$access_token->getToken()] = $access_token;
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
