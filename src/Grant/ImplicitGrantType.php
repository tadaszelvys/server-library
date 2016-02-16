<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Grant;

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Behaviour\HasTokenTypeParameterSupport;
use OAuth2\Endpoint\Authorization;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;

final class ImplicitGrantType implements ResponseTypeSupportInterface
{
    use HasTokenTypeManager;
    use HasAccessTokenManager;
    use HasTokenTypeParameterSupport;

    /**
     * ImplicitGrantType constructor.
     *
     * @param \OAuth2\Token\TokenTypeManagerInterface   $token_type_manager
     * @param \OAuth2\Token\AccessTokenManagerInterface $access_token_manager
     */
    public function __construct(TokenTypeManagerInterface $token_type_manager,
                                AccessTokenManagerInterface $access_token_manager
    ) {
        $this->setTokenTypeManager($token_type_manager);
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
        return self::RESPONSE_TYPE_MODE_FRAGMENT;
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeAuthorization(array &$response_parameters, Authorization $authorization)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function prepareAuthorization(Authorization $authorization)
    {
        $token_type = $this->getTokenTypeFromRequest($authorization->getQueryParams());

        $token = $this->getAccessTokenManager()->createAccessToken(
            $authorization->getClient(),
            $authorization->getEndUser(),
            $token_type->getTokenTypeInformation(),
            $authorization->getQueryParams(),
            $authorization->getScopes()
        );

        return $token->toArray();
    }
}
