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

namespace OAuth2\Command\RefreshToken;

use OAuth2\Model\RefreshToken\RefreshTokenRepositoryInterface;

final class CreateRefreshTokenCommandHandler
{
    /**
     * @var RefreshTokenRepositoryInterface
     */
    private $refreshTokenRepository;

    /**
     * CreateRefreshTokenCommandHandler constructor.
     *
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     */
    public function __construct(RefreshTokenRepositoryInterface $refreshTokenRepository)
    {
        $this->refreshTokenRepository = $refreshTokenRepository;
    }

    /**
     * @param CreateRefreshTokenCommand $command
     */
    public function handle(CreateRefreshTokenCommand $command)
    {
        $refreshToken = $this->refreshTokenRepository->create(
            $command->getUserAccountId(),
            $command->getClientId(),
            $command->getParameters(),
            $command->getExpiresAt(),
            $command->getScopes(),
            $command->getMetadatas()
        );
        $this->refreshTokenRepository->save($refreshToken);
    }
}
