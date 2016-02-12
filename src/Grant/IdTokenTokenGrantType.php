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

use Assert\Assertion;
use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasIdTokenManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Endpoint\Authorization;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\IdTokenManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;

final class IdTokenTokenGrantType implements ResponseTypeSupportInterface
{
    use HasTokenTypeManager;
    use HasIdTokenManager;
    use HasAccessTokenManager;

    /**
     * @var bool
     */
    private $access_token_type_parameter_allowed = false;

    /**
     * IdTokenTokenGrantType constructor.
     *
     * @param \OAuth2\Token\TokenTypeManagerInterface      $token_type_manager
     * @param \OAuth2\Token\IdTokenManagerInterface        $id_token_manager
     * @param \OAuth2\Token\AccessTokenManagerInterface    $access_token_manager
     */
    public function __construct(TokenTypeManagerInterface $token_type_manager,
                                IdTokenManagerInterface $id_token_manager,
                                AccessTokenManagerInterface $access_token_manager
    ) {
        $this->setTokenTypeManager($token_type_manager);
        $this->setIdTokenManager($id_token_manager);
        $this->setAccessTokenManager($access_token_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return 'id_token token';
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
        //OpenId Connect checks here

        if (true === $this->isAccessTokenTypeParameterAllowed() && array_key_exists('token_type', $authorization->getQueryParams())) {
            $token_type = $this->getTokenTypeManager()->getTokenType($authorization->getQueryParams()['token_type']);
        } else {
            $token_type = $this->getTokenTypeManager()->getDefaultTokenType();
        }

        $access_token = $this->getAccessTokenManager()->createAccessToken(
            $authorization->getClient(),
            $authorization->getEndUser(),
            $token_type->getTokenTypeInformation(),
            $authorization->getQueryParams(),
            $authorization->getScopes()
        );

        $id_token = $this->getIdTokenManager()->createIdToken(
            $authorization->getClient(),
            $authorization->getEndUser(),
            $token_type->getTokenTypeInformation(),
            [],
            $access_token,
            null
        );

        return array_merge(
            $access_token->toArray(),
            $id_token->toArray()
        );
    }

    /**
     * @return bool
     */
    public function isAccessTokenTypeParameterAllowed()
    {
        return $this->access_token_type_parameter_allowed;
    }

    /**
     *
     */
    public function allowAccessTokenTypeParameter()
    {
        $this->access_token_type_parameter_allowed = true;;
    }

    /**
     *
     */
    public function disallowAccessTokenTypeParameter()
    {
        $this->access_token_type_parameter_allowed = true;;
    }
}
