<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Endpoint\Authorization;
use OAuth2\Token\AccessTokenManagerInterface;

final class ImplicitGrantType implements ResponseTypeSupportInterface
{
    use HasAccessTokenManager;

    /**
     * ImplicitGrantType constructor.
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
    public function getResponseType()
    {
        return 'token';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode()
    {
        return 'fragment';
    }

    /**
     * {@inheritdoc}
     */
    public function grantAuthorization(Authorization $authorization)
    {
        $token = $this->getAccessTokenManager()->createAccessToken(
            $authorization->getClient(),
            $authorization->getEndUser(),
            $authorization->getScopes()
        );

        return $token->toArray();
    }
}
