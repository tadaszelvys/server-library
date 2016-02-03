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
use OAuth2\Behaviour\HasIdTokenManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Endpoint\Authorization;
use OAuth2\Token\IdTokenManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;

final class IdTokenGrantType implements ResponseTypeSupportInterface
{
    use HasTokenTypeManager;
    use HasIdTokenManager;

    /**
     * @var bool
     */
    private $access_token_type_parameter_allowed = false;

    /**
     * IdTokenGrantType constructor.
     *
     * @param \OAuth2\Token\TokenTypeManagerInterface      $token_type_manager
     * @param \OAuth2\Token\IdTokenManagerInterface        $id_token_manager
     */
    public function __construct(TokenTypeManagerInterface $token_type_manager,
                                IdTokenManagerInterface $id_token_manager
    ) {
        $this->setTokenTypeManager($token_type_manager);
        $this->setIdTokenManager($id_token_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return 'id_token';
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

        $id_token = $this->getIdTokenManager()->createIdToken(
            $authorization->getClient(),
            $authorization->getEndUser(),
            $token_type->getTokenTypeInformation(),
            [],
            null,
            null
        );

        return $id_token->toArray();
    }

    /**
     * @return bool
     */
    public function isAccessTokenTypeParameterAllowed()
    {
        return $this->access_token_type_parameter_allowed;
    }

    /**
     * @param bool $access_token_type_parameter_allowed
     */
    public function setAccessTokenTypeParameterAllowed($access_token_type_parameter_allowed)
    {
        Assertion::boolean($access_token_type_parameter_allowed);
        $this->access_token_type_parameter_allowed = $access_token_type_parameter_allowed;;
    }
}
