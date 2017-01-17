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

namespace OAuth2\Command\InitialAccessToken;

use OAuth2\Event\InitialAccessToken\InitialAccessTokenRevokedEvent;
use OAuth2\Model\InitialAccessToken\InitialAccessTokenRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class RevokeInitialAccessTokenCommandHandler
{
    /**
     * @var InitialAccessTokenRepositoryInterface
     */
    private $initialAccessTokenRepository;

    /**
     * @var RecordsMessages
     */
    private $messageRecorder;

    /**
     * CreateClientCommandHandler constructor.
     *
     * @param InitialAccessTokenRepositoryInterface $initialAccessTokenRepository
     * @param RecordsMessages                       $messageRecorder
     */
    public function __construct(InitialAccessTokenRepositoryInterface $initialAccessTokenRepository, RecordsMessages $messageRecorder)
    {
        $this->initialAccessTokenRepository = $initialAccessTokenRepository;
        $this->messageRecorder = $messageRecorder;
    }

    /**
     * @param RevokeInitialAccessTokenCommand $command
     */
    public function handle(RevokeInitialAccessTokenCommand $command)
    {
        $accessToken = $command->getInitialAccessToken();
        $this->initialAccessTokenRepository->revoke($accessToken);
        $event = InitialAccessTokenRevokedEvent::create($accessToken);
        $this->messageRecorder->record($event);
    }
}
