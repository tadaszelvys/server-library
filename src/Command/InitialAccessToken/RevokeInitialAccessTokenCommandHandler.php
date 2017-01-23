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

final class RevokeInitialAccessTokenCommandHandler
{
    /**
     * @var InitialAccessTokenRepositoryInterface
     */
    private $initialAccessTokenRepository;

    /**
     * CreateClientCommandHandler constructor.
     *
     * @param InitialAccessTokenRepositoryInterface $initialAccessTokenRepository
     */
    public function __construct(InitialAccessTokenRepositoryInterface $initialAccessTokenRepository)
    {
        $this->initialAccessTokenRepository = $initialAccessTokenRepository;
    }

    /**
     * @param RevokeInitialAccessTokenCommand $command
     */
    public function handle(RevokeInitialAccessTokenCommand $command)
    {
        $accessTokenId = $command->getInitialAccessTokenId();
        $this->initialAccessTokenRepository->revoke($accessTokenId);
    }
}
