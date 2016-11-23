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

use Assert\Assertion;
use Jose\Object\JWTInterface;
use OAuth2\Behaviour\HasAccessTokenManager;
use OAuth2\Behaviour\HasRefreshTokenManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Token\AccessTokenInterface;
use OAuth2\Token\AccessTokenManagerInterface;
use OAuth2\Token\JWTAccessTokenInterface;
use OAuth2\Token\RefreshTokenInterface;
use OAuth2\Token\RefreshTokenManagerInterface;
use OAuth2\Token\TokenInterface;

class AccessToken implements IntrospectionTokenTypeInterface, RevocationTokenTypeInterface
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
     * @param \OAuth2\Token\AccessTokenManagerInterface $access_token_manager
     */
    public function __construct(AccessTokenManagerInterface $access_token_manager)
    {
        $this->setAccessTokenManager($access_token_manager);
    }

    /**
     * {@inheritdoc}
     */
    public function enableRefreshTokenSupport(RefreshTokenManagerInterface $refresh_token_manager)
    {
        $this->setRefreshTokenManager($refresh_token_manager);
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
                && true === $this->hasRefreshTokenManager()) {
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
    public function introspectToken(TokenInterface $token, ClientInterface $client)
    {
        if (!$token instanceof AccessTokenInterface) {
            return [];
        }

        $result = [
            'active'     => !$token->hasExpired(),
            'client_id'  => $token->getClientPublicId(),
            'token_type' => $token->getTokenTypeParameter('token_type'),
            'exp'        => $token->getExpiresAt(),
        ];

        // If the client is the subject, we add this information.
        //
        // The subject is not added if the client is not a resource owner.
        // The reason is that if the client received an ID Token, the subject may have been computed (pairwise) and
        // the subject returned here may be different. As per the OpenID Connect specification, the client must reject the token
        // if subject are different and we want to avoid this case.
        if ($client->getPublicId() === $token->getResourceOwnerPublicId()) {
            $result['sub'] = $token->getResourceOwnerPublicId();
        }

        // If the client is a resource server, we return all the information stored in the access token including the metadata
        if ($client->has('is_resource_server') && true === $client->get('is_resource_server')) {
            $result['sub'] = $token->getResourceOwnerPublicId();
        }

        if (!empty($token->getScope())) {
            $result['scp'] = $token->getScope();
        }
        if ($token instanceof JWTAccessTokenInterface) {
            $result = array_merge($result, $this->getJWTInformation($token->getJWS()));
        }

        return $result;
    }

    /**
     * @param \Jose\Object\JWTInterface $token
     *
     * @return array
     */
    protected function getJWTInformation(JWTInterface $token)
    {
        $result = [];
        foreach (['jti', 'iat', 'nbf', 'aud', 'iss'] as $key) {
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

    public function enableRefreshTokensRevocationWithAccessTokens()
    {
        Assertion::true($this->hasRefreshTokenManager(), 'The refresh token support is not enabled.');
        $this->refresh_tokens_revoked_with_access_tokens = true;
    }

    public function disableRefreshTokensRevocationWithAccessTokens()
    {
        $this->refresh_tokens_revoked_with_access_tokens = false;
    }
}
