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

namespace OAuth2\Command\InitialAccessToken;

use OAuth2\Model\InitialAccessToken\InitialAccessTokenRepositoryInterface;

final class CreateInitialAccessTokenCommandHandler
{
    /**
     * @var InitialAccessTokenRepositoryInterface
     */
    private $initialAccessTokenRepository;

    /**
     * CreateInitialAccessTokenCommandHandler constructor.
     *
     * @param InitialAccessTokenRepositoryInterface $initialAccessTokenRepository
     */
    public function __construct(InitialAccessTokenRepositoryInterface $initialAccessTokenRepository)
    {
        $this->initialAccessTokenRepository = $initialAccessTokenRepository;
    }

    /**
     * @param CreateInitialAccessTokenCommand $command
     */
    public function handle(CreateInitialAccessTokenCommand $command)
    {
        $initialAccessToken = $this->initialAccessTokenRepository->create(
            $command->getUserAccountId(),
            $command->getExpiresAt()
        );
        $this->initialAccessTokenRepository->save($initialAccessToken);
    }
}
