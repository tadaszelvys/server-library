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
    public function prepareAuthorization(Authorization $authorization)
    {
        if (!in_array('openid', $authorization->getScopes())) {
            return [];
        }
        if (!array_key_exists('nonce', $authorization->getQueryParams())) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'The parameter "nonce" is mandatory using "id_token" response type.');
        }

        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeAuthorization(array &$response_parameters, Authorization $authorization, $redirect_uri)
    {
        $params = $authorization->getQueryParams();

        $id_token = $this->getIdTokenManager()->createIdToken(
            $authorization->getClient(),
            $authorization->getUser(),
            $redirect_uri,
            $authorization->getScopes(),
            ['nonce' => $params['nonce']],
            $authorization->hasData('access_token') ? $authorization->getData('access_token') : null,
            $authorization->hasData('code') ? $authorization->getData('code') : null
        );
        
        $authorization->setData('id_token', $id_token);

        $response_parameters = array_merge(
            $response_parameters,
            $id_token->toArray()
        );
    }
}
