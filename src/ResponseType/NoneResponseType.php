<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResponseType;

use OAuth2\Endpoint\Authorization\Authorization;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use OAuth2\TokenType\TokenTypeManagerInterface;
use Psr\Http\Message\UriInterface;

/**
 * This response type has been introduced by OpenID Connect
 * It creates an access token, but does not returns anything.
 *
 * At this time, this response type is not complete, because it always redirect the client.
 * But if no redirect URI is specified, no redirection should occurred as per OpenID Connect specification.
 *
 * @see http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#none
 */
final class NoneResponseType implements ResponseTypeInterface
{
    /**
     * @var TokenTypeManagerInterface
     */
    private $tokenTypeManager;

    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenManager;

    /**
     * NoneResponseType constructor.
     *
     * @param TokenTypeManagerInterface      $tokenTypeManager
     * @param AccessTokenRepositoryInterface $accessTokenManager
     */
    public function __construct(TokenTypeManagerInterface $tokenTypeManager, AccessTokenRepositoryInterface $accessTokenManager)
    {
        $this->tokenTypeManager = $tokenTypeManager;
        $this->accessTokenManager = $accessTokenManager;
    }

    /**
     * {@inheritdoc}
     */
    public function getAssociatedGrantTypes(): array
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseType(): string
    {
        return 'none';
    }

    /**
     * {@inheritdoc}
     */
    public function getResponseMode(): string
    {
        return self::RESPONSE_TYPE_MODE_QUERY;
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeAuthorization(array &$response_parameters, Authorization $authorization, UriInterface $redirectUri)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function prepareAuthorization(Authorization $authorization): array
    {
        $token_type = $this->getTokenTypeFromRequest($authorization->getQueryParams());

        $token = $this->accessTokenManager->createAccessToken(
            $authorization->getClient(),
            $authorization->getUserAccount(),
            $token_type->getTokenTypeInformation(),
            $authorization->getQueryParams(),
            $authorization->getScopes(),
            null, // Refresh token
            null, // Resource Server
            ['redirect_uri' => $authorization->getQueryParam('redirect_uri')]
        );

        $authorization->setData('access_token', $token);

        //Event

        return [];
    }
}
