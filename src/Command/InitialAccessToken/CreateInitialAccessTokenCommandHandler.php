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

use OAuth2\Event\InitialAccessToken\InitialAccessTokenCreatedEvent;
use OAuth2\Model\InitialAccessToken\InitialAccessTokenRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class CreateInitialAccessTokenCommandHandler
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
     * CreateInitialAccessTokenCommandHandler constructor.
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
     * @param CreateInitialAccessTokenCommand $command
     */
    public function handle(CreateInitialAccessTokenCommand $command)
    {
        $initialAccessToken = $this->initialAccessTokenRepository->create(
            $command->getUserAccountId(),
            $command->getExpiresAt()
        );
        $this->initialAccessTokenRepository->save($initialAccessToken);
        $event = InitialAccessTokenCreatedEvent::create($initialAccessToken);
        $this->messageRecorder->record($event);
    }
}
