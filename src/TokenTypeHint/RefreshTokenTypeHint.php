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

namespace OAuth2\TokenTypeHint;

use Assert\Assertion;
use OAuth2\Command\AccessToken\RevokeAccessTokenCommand;
use OAuth2\Command\RefreshToken\RevokeRefreshTokenCommand;
use OAuth2\Model\RefreshToken\RefreshToken;
use OAuth2\Model\RefreshToken\RefreshTokenId;
use OAuth2\Model\RefreshToken\RefreshTokenRepositoryInterface;
use OAuth2\Model\Token\Token;
use SimpleBus\Message\Bus\MessageBus;

class RefreshTokenTypeHint implements TokenTypeHintInterface
{
    /**
     * @var RefreshTokenRepositoryInterface
     */
    private $refreshTokenRepository;

    /**
     * @var MessageBus
     */
    private $commandBus;

    /**
     * @var bool
     */
    private $revokeAccessTokens;

    /**
     * RefreshToken constructor.
     *
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     * @param MessageBus                      $commandBus
     * @param bool                            $revokeAccessTokens
     */
    public function __construct(RefreshTokenRepositoryInterface $refreshTokenRepository, MessageBus $commandBus, bool $revokeAccessTokens)
    {
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->commandBus = $commandBus;
        $this->revokeAccessTokens = $revokeAccessTokens;
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
    public function find(string $token)
    {
        return $this->refreshTokenRepository->find(RefreshTokenId::create($token));
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(Token $token)
    {
        if (!$token instanceof RefreshToken) {
            return;
        }
        $revokeRefreshTokenCommand = RevokeRefreshTokenCommand::create($token);
        $this->commandBus->handle($revokeRefreshTokenCommand);
        $accessTokens = $token->getAccessTokens();
        if (!empty($accessTokens) && true === $this->revokeAccessTokens) {
            foreach ($accessTokens as $accessToken) {
                $revokeAccessTokenCommand = RevokeAccessTokenCommand::create($accessToken);
                $this->commandBus->handle($revokeAccessTokenCommand);
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function introspect(Token $token): array
    {
        Assertion::isInstanceOf($token, RefreshToken::class);

        $result = [
            'active'     => !$token->hasExpired(),
            'client_id'  => $token->getClient()->getId(),
            'exp'        => $token->getExpiresAt()->getTimestamp(),
        ];

        if (!empty($token->getScopes())) {
            $result['scp'] = $token->getScopes();
        }

        return $result;
    }
}
