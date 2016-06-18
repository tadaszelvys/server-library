<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Security\Handler;

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Token\AccessTokenManagerInterface;

/**
 * This class will try to get the access token using the access token manager
 * It is needed when the resource server and the authorization server are running together.
 *
 * If the resource server and the authorization server are on different applications, then you should use the
 * IntrospectionEndpointHandler class (to be written).
 */
final class AccessTokenManagerHandler implements AccessTokenHandlerInterface
{
    use HasAccessTokenManager;

    /**
     * AccessTokenManagerHandler constructor.
     *
     * @param \OAuth2\Token\AccessTokenManagerInterface $access_token_manager
     */
    public function __construct(AccessTokenManagerInterface $access_token_manager)
    {
        $this->setAccessTokenManager($access_token_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessToken($token)
    {
        return $this->getAccessTokenManager()->getAccessToken($token);
    }
}
