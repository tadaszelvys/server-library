<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\TokenTypeHint;

use Assert\Assertion;
use OAuth2\Command\AccessToken\RevokeAccessTokenCommand;
use OAuth2\Command\RefreshToken\RevokeRefreshTokenCommand;
use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\AccessToken\AccessTokenId;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use OAuth2\Model\Token\Token;
use SimpleBus\Message\Bus\MessageBus;

class AccessTokenTypeHint implements TokenTypeHintInterface
{
    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var MessageBus
     */
    private $commandBus;

    /**
     * @var bool
     */
    private $revokeRefreshToken;

    /**
     * AccessToken constructor.
     *
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     * @param MessageBus                     $commandBus
     * @param bool                           $revokeRefreshToken
     */
    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository, MessageBus $commandBus, bool $revokeRefreshToken)
    {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->commandBus = $commandBus;
        $this->revokeRefreshToken = $revokeRefreshToken;
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
    public function find(string $token)
    {
        return $this->accessTokenRepository->find(AccessTokenId::create($token));
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(Token $token)
    {
        if (!$token instanceof AccessToken) {
            return;
        }
        $revokeAccessTokenCommand = RevokeAccessTokenCommand::create($token);
        $this->commandBus->handle($revokeAccessTokenCommand);
        $refreshToken = $token->getRefreshToken();
        if (null !== $refreshToken && true === $this->revokeRefreshToken) {
            $revokeRefreshTokenCommand = RevokeRefreshTokenCommand::create($refreshToken);
            $this->commandBus->handle($revokeRefreshTokenCommand);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function introspect(Token $token): array
    {
        $accessToken = $this->find($token);
        Assertion::notNull($accessToken);

        $result = [
            'active'     => !$accessToken->hasExpired(),
            'client_id'  => $accessToken->getClient()->getId()->getValue(),
            'token_type' => $accessToken->getParameter('token_type'),
            'exp'        => $accessToken->getExpiresAt(),
        ];

        if (!empty($accessToken->getScopes())) {
            $result['scp'] = $accessToken->getScopes();
        }

        return $result;
    }
}
