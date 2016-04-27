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

use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasTokenTypeManager;
use OAuth2\Behaviour\HasTokenTypeParameterSupport;
use OAuth2\Endpoint\Authorization;
use OAuth2\Grant\ResponseTypeSupportInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\TokenTypeManagerInterface;

/**
 * This response type has been introduced by OpenID Connect
 * It creates an access token, but does not returns anything.
 *
 * At this time, this response type is not complete, because it always redirect the client.
 * But if no redirect URI is specified, no redirection should occurred as per OpenID Connect specification.
 *
 * @see http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
 */
final class NoneResponseType implements ResponseTypeSupportInterface
{
    use HasTokenTypeManager;
    use HasAccessTokenManager;
    use HasTokenTypeParameterSupport;

    /**
     * @var \OAuth2\OpenIDConnect\NoneResponseTypeListenerInterface[]
     */
    private $listeners = [];

    /**
     * NoneResponseType constructor.
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
     * @param \OAuth2\OpenIDConnect\NoneResponseTypeListenerInterface $listener
     */
    public function addListener(NoneResponseTypeListenerInterface $listener)
    {
        $this->listeners[] = $listener;
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType()
    {
        return 'none';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode()
    {
        return self::RESPONSE_TYPE_MODE_QUERY;
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeAuthorization(array &$response_parameters, Authorization $authorization, $redirect_uri)
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
            $authorization->getUser(),
            $token_type->getTokenTypeInformation(),
            $authorization->getScopes()
        );
        
        $authorization->setData('access_token', $token);

        foreach ($this->listeners as $listener) {
            $listener->call($token);
        }

        return [];
    }
}
