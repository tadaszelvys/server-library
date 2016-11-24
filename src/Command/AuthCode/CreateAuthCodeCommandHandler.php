<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\AuthCode;

use OAuth2\Event\AuthCode\AuthCodeCreatedEvent;
use OAuth2\Model\AuthCode\AuthCodeRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class CreateAuthCodeCommandHandler
{
    /**
     * @var AuthCodeRepositoryInterface
     */
    private $authCodeRepository;

    /**
     * @var RecordsMessages
     */
    private $messageRecorder;

    /**
     * CreateClientCommandHandler constructor.
     * @param AuthCodeRepositoryInterface $authCodeRepository
     * @param RecordsMessages $messageRecorder
     */
    public function __construct(AuthCodeRepositoryInterface $authCodeRepository, RecordsMessages $messageRecorder)
    {
        $this->authCodeRepository = $authCodeRepository;
        $this->messageRecorder = $messageRecorder;
    }

    /**
     * @param CreateAuthCodeCommand $command
     */
    public function handle(CreateAuthCodeCommand $command)
    {

        $authCode = $this->authCodeRepository->create(
            $command->getClient(),
            $command->getUserAccount(),
            $command->getQueryParameters(),
            $command->getExpiresAt(),
            $command->getParameters(),
            $command->getScopes(),
            $command->getMetadatas()
        );
        $this->authCodeRepository->save($authCode);
        $event = AuthCodeCreatedEvent::create($authCode);
        $this->messageRecorder->record($event);
    }
}
