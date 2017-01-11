<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\RefreshToken;

use OAuth2\Event\RefreshToken\RefreshTokenCreatedEvent;
use OAuth2\Model\RefreshToken\RefreshTokenRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class CreateRefreshTokenCommandHandler
{
    /**
     * @var RefreshTokenRepositoryInterface
     */
    private $refreshTokenRepository;

    /**
     * @var RecordsMessages
     */
    private $messageRecorder;

    /**
     * CreateRefreshTokenCommandHandler constructor.
     *
     * @param RefreshTokenRepositoryInterface $refreshTokenRepository
     * @param RecordsMessages                 $messageRecorder
     */
    public function __construct(RefreshTokenRepositoryInterface $refreshTokenRepository, RecordsMessages $messageRecorder)
    {
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->messageRecorder = $messageRecorder;
    }

    /**
     * @param CreateRefreshTokenCommand $command
     */
    public function handle(CreateRefreshTokenCommand $command)
    {
        $refreshToken = $this->refreshTokenRepository->create(
            $command->getUserAccount(),
            $command->getClient(),
            $command->getParameters(),
            $command->getExpiresAt(),
            $command->getMetadatas()
        );
        $this->refreshTokenRepository->save($refreshToken);
        $event = RefreshTokenCreatedEvent::create($refreshToken);
        $this->messageRecorder->record($event);
    }
}
