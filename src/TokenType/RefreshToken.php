<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\TokenType;

use OAuth2\Model\RefreshToken\RefreshTokenRepositoryInterface;

class RefreshToken implements IntrospectionTokenTypeInterface, RevocationTokenTypeInterface
{
    /**
     * RefreshToken constructor.
     *
     * @param RefreshTokenRepositoryInterface $refresh_token_manager
     */
    public function __construct(RefreshTokenRepositoryInterface $refresh_token_manager)
    {
        $this->setRefreshTokenManager($refresh_token_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeHint(): string
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
    public function introspectToken(TokenInterface $token, ClientInterface $client)
    {
        if (!$token instanceof RefreshTokenInterface) {
            return [];
        }

        $result = [
            'active'     => !$token->hasExpired(),
            'client_id'  => $token->getClientPublicId(),
            'exp'        => $token->getExpiresAt(),
        ];
        if (!empty($token->getScope())) {
            $result['scp'] = $token->getScope();
        }

        return $result;
    }
}
