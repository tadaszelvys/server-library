<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Endpoint\Authorization;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Grant\ResponseTypeSupportInterface;
use OAuth2\Token\TokenTypeManagerInterface;

final class IdTokenGrantType implements ResponseTypeSupportInterface
{
    use HasTokenTypeManager;
    use HasIdTokenManager;
    use HasExceptionManager;

    /**
     * @var bool
     */
    private $access_token_type_parameter_allowed = false;

    /**
     * IdTokenGrantType constructor.
     *
     * @param \OAuth2\Token\TokenTypeManagerInterface       $token_type_manager
     * @param \OAuth2\OpenIDConnect\IdTokenManagerInterface $id_token_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface   $exception_manager
     */
    public function __construct(TokenTypeManagerInterface $token_type_manager,
                                IdTokenManagerInterface $id_token_manager,
                                ExceptionManagerInterface $exception_manager
    ) {
        $this->setTokenTypeManager($token_type_manager);
        $this->setIdTokenManager($id_token_manager);
        $this->setExceptionManager($exception_manager);
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
        return self::RESPONSE_TYPE_MODE_FRAGMENT;
    }

    /**
     * {@inheritdoc}
     */
    public function grantAuthorization(Authorization $authorization)
    {
        if (!in_array('openid', $authorization->getScopes())) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The scope "openid" is mandatory with response type "id_token".');
        }
        $params = $authorization->getQueryParams();
        if (!array_key_exists('nonce', $params)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "nonce" is missing.');
        }

        if (true === $this->isAccessTokenTypeParameterAllowed() && array_key_exists('token_type', $authorization->getQueryParams())) {
            $token_type = $this->getTokenTypeManager()->getTokenType($authorization->getQueryParams()['token_type']);
        } else {
            $token_type = $this->getTokenTypeManager()->getDefaultTokenType();
        }

        $token_type_information = $token_type->getTokenTypeInformation();

        $id_token = $this->getIdTokenManager()->createIdToken(
            $authorization->getClient(),
            $authorization->getEndUser(),
            $token_type_information,
            ['nonce' => $params['nonce']],
            null,
            null
        );

        return array_merge(
            $id_token->toArray(),
            $token_type_information
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
        $this->access_token_type_parameter_allowed = true;
    }

    /**
     *
     */
    public function disallowAccessTokenTypeParameter()
    {
        $this->access_token_type_parameter_allowed = true;
    }
}
