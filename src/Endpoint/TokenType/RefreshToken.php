<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\TokenType;

use Jose\Object\JWTInterface;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\Token\TokenInterface;

final class RefreshToken implements IntrospectionTokenTypeInterface, RevocationTokenTypeInterface
{
    use HasRefreshTokenManager;

    /**
     * RefreshToken constructor.
     *
     * @param \OAuth2\Token\RefreshTokenManagerInterface $refresh_token_manager
     */
    public function __construct(RefreshTokenManagerInterface $refresh_token_manager)
    {
        $this->setRefreshTokenManager($refresh_token_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeHint()
    {
        return 'refresh_token';
    }

    /**
     * {@inheritdoc}
     */
    public function getToken($token)
    {
        return $this->getRefreshTokenManager()->getRefreshToken($token);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeToken(TokenInterface $token)
    {
        if ($token instanceof RefreshTokenInterface) {
            $this->getRefreshTokenManager()->revokeRefreshToken($token);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function introspectToken(TokenInterface $token)
    {
        if (!$token instanceof RefreshTokenInterface) {
            return [];
        }

        $result = [
            'active'     => !$token->hasExpired() && !$token->isUsed(),
            'client_id'  => $token->getClientPublicId(),
            'exp'        => $token->getExpiresAt(),
            'sub'        => $token->getResourceOwnerPublicId(),
        ];
        if (!empty($token->getScope())) {
            $result['scope'] = $token->getScope();
        }

        return $result;
    }
}
