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
use OAuth2\Behaviour\HasConfiguration;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Configuration\ConfigurationInterface;
use OAuth2\Endpoint\Authorization;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;

final class ImplicitGrantType implements ResponseTypeSupportInterface
{
    use HasConfiguration;
    use HasTokenTypeManager;
    use HasAccessTokenManager;

    /**
     * ImplicitGrantType constructor.
     *
     * @param \OAuth2\Configuration\ConfigurationInterface $configuration
     * @param \OAuth2\Token\TokenTypeManagerInterface      $token_type_manager
     * @param \OAuth2\Token\AccessTokenManagerInterface    $access_token_manager
     */
    public function __construct(ConfigurationInterface $configuration,
                                TokenTypeManagerInterface $token_type_manager,
                                AccessTokenManagerInterface $access_token_manager
    ) {
        $this->setConfiguration($configuration);
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
        return 'fragment';
    }

    /**
     * {@inheritdoc}
     */
    public function grantAuthorization(Authorization $authorization)
    {
        if (true === $this->getConfiguration()->get('allow_access_token_type_parameter', false) && array_key_exists('token_type', $authorization->getQueryParams())) {
            $token_type = $this->getTokenTypeManager()->getTokenType($authorization->getQueryParams()['token_type']);
        } else {
            $token_type = $this->getTokenTypeManager()->getDefaultTokenType();
        }

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
