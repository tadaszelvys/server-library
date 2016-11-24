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

use Assert\Assertion;
use Jose\Object\JWTInterface;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;

class AccessToken implements IntrospectionTokenTypeInterface, RevocationTokenTypeInterface
{
    /**
     * @var bool
     */
    private $refreshTokensRevokedWithAccessTokens = true;

    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var RefreshTokenRepositoryInterface
     */
    private $refreshTokenRepository;

    /**
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     */
    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository)
    {
        $this->accessTokenRepository = $accessTokenRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function enableRefreshTokenSupport(RefreshTokenRepositoryInterface $refreshTokenRepository)
    {
        $this->refreshTokenRepository = $refreshTokenRepository;
    }

    /**
     * {@inheritdoc}
     */
    public function getTokenTypeHint(): string
    {
        return 'access_token';
    }

    /**
     * {@inheritdoc}
     */
    public function getToken($token)
    {
        return $this->accessTokenRepository->getAccessToken($token);
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
            $this->accessTokenRepository->revokeAccessToken($token);
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
        return $this->refreshTokensRevokedWithAccessTokens;
    }

    public function enableRefreshTokensRevocationWithAccessTokens()
    {
        Assertion::true($this->hasRefreshTokenManager(), 'The refresh token support is not enabled.');
        $this->refreshTokensRevokedWithAccessTokens = true;
    }

    public function disableRefreshTokensRevocationWithAccessTokens()
    {
        $this->refreshTokensRevokedWithAccessTokens = false;
    }
}
