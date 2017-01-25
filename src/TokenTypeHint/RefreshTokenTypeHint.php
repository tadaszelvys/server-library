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

use OAuth2\Command\RefreshToken\RevokeRefreshTokenCommand;
use OAuth2\Model\RefreshToken\RefreshTokenId;
use OAuth2\Model\RefreshToken\RefreshTokenRepositoryInterface;
use OAuth2\Model\Token\TokenId;
use SimpleBus\Message\Bus\MessageBus;

final class RefreshTokenTypeHint implements TokenTypeHintInterface
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
     * RefreshToken constructor.
     *
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     * @param MessageBus                      $commandBus
     */
    public function __construct(RefreshTokenRepositoryInterface $refreshTokenRepository, MessageBus $commandBus)
    {
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->commandBus = $commandBus;
    }

    /**
     * {@inheritdoc}
     */
    public function hint(): string
    {
        return 'refresh_token';
    }

    /**
     * {@inheritdoc}
     */
    public function find(string $token)
    {
        $id = RefreshTokenId::create($token);

        return $this->refreshTokenRepository->find($id);
    }

    /**
     * {@inheritdoc}
     */
    public function revoke(TokenId $tokenId)
    {
        if (!$tokenId instanceof RefreshTokenId) {
            return;
        }
        $revokeRefreshTokenCommand = RevokeRefreshTokenCommand::create($tokenId);
        $this->commandBus->handle($revokeRefreshTokenCommand);
    }

    /**
     * {@inheritdoc}
     */
    public function introspect(TokenId $tokenId): array
    {
        if (!$tokenId instanceof RefreshTokenId || !$this->refreshTokenRepository->has($tokenId)) {
            return [
                'active' => false,
            ];
        }
        $refreshToken = $this->refreshTokenRepository->find($tokenId);

        $result = [
            'active'     => !$refreshToken->hasExpired(),
            'client_id'  => $refreshToken->getClientId(),
            'exp'        => $refreshToken->getExpiresAt()->getTimestamp(),
        ];

        if (!empty($refreshToken->getScopes())) {
            $result['scp'] = $refreshToken->getScopes();
        }

        return $result;
    }
}
