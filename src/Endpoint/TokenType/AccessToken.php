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
use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\Token\TokenInterface;

final class AccessToken implements IntrospectionTokenTypeInterface, RevocationTokenTypeInterface
{
    use HasAccessTokenManager;
    use HasRefreshTokenManager;

    /**
     * @var bool
     */
    private $refresh_tokens_revoked_with_access_tokens = true;

    /**
     * AccessToken constructor.
     *
     * @param \OAuth2\Token\AccessTokenManagerInterface       $access_token_manager
     * @param \OAuth2\Token\RefreshTokenManagerInterface|null $refresh_token_manager
     */
    public function __construct(AccessTokenManagerInterface $access_token_manager, RefreshTokenManagerInterface $refresh_token_manager = null)
    {
        $this->setAccessTokenManager($access_token_manager);
        if ($refresh_token_manager instanceof RefreshTokenManagerInterface) {
            $this->setRefreshTokenManager($refresh_token_manager);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeHint()
    {
        return 'access_token';
    }

    /**
     * {@inheritdoc}
     */
    public function getToken($token)
    {
        return $this->getAccessTokenManager()->getAccessToken($token);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeToken(TokenInterface $token)
    {
        if ($token instanceof AccessTokenInterface) {
            if (true === $this->areRefreshTokensRevokedWithAccessTokens()
                && null !== $token->getRefreshToken()
                && $this->getRefreshTokenManager() instanceof RefreshTokenManagerInterface) {
                $refresh_token = $this->getRefreshTokenManager()->getRefreshToken($token->getRefreshToken());
                if ($refresh_token instanceof RefreshTokenInterface) {
                    $this->getRefreshTokenManager()->revokeRefreshToken($refresh_token);
                }
            }
            $this->getAccessTokenManager()->revokeAccessToken($token);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function introspectToken(TokenInterface $token)
    {
        if (!$token instanceof AccessTokenInterface) {
            return [];
        }

        $result = [
            'active'     => !$token->hasExpired(),
            'client_id'  => $token->getClientPublicId(),
            'token_type' => $token->getTokenType(),
            'exp'        => $token->getExpiresAt(),
            'sub'        => $token->getResourceOwnerPublicId(),
        ];
        if (!empty($token->getScope())) {
            $result['scope'] = $token->getScope();
        }
        if ($token instanceof JWTInterface) {
            $result = array_merge($result, $this->getJWTInformation($token));
        }

        return $result;
    }

    /**
     * @param \Jose\Object\JWTInterface $token
     *
     * @return array
     */
    private function getJWTInformation(JWTInterface $token)
    {
        $result = [];
        foreach (['iat', 'nbf', 'aud', 'iss', 'jti'] as $key) {
            if ($token->hasClaim($key)) {
                $result[$key] = $token->getClaim($key);
            }
        }

        return $result;
    }

    public function areRefreshTokensRevokedWithAccessTokens()
    {
        return $this->refresh_tokens_revoked_with_access_tokens;
    }

    /**
     *
     */
    public function enableRefreshTokensRevocationWithAccessTokens()
    {
        $this->refresh_tokens_revoked_with_access_tokens = true;
    }

    /**
     *
     */
    public function disableRefreshTokensRevocationWithAccessTokens()
    {
        $this->refresh_tokens_revoked_with_access_tokens = false;
    }
}
