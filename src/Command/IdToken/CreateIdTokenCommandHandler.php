<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\IdToken;

use OAuth2\Event\IdToken\IdTokenCreatedEvent;
use OAuth2\Model\IdToken\IdTokenRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class CreateIdTokenCommandHandler
{
    /**
     * @var IdTokenRepositoryInterface
     */
    private $idTokenRepository;

    /**
     * @var RecordsMessages
     */
    private $messageRecorder;

    /**
     * CreateClientCommandHandler constructor.
     *
     * @param IdTokenRepositoryInterface $idTokenRepository
     * @param RecordsMessages            $messageRecorder
     */
    public function __construct(IdTokenRepositoryInterface $idTokenRepository, RecordsMessages $messageRecorder)
    {
        $this->idTokenRepository = $idTokenRepository;
        $this->messageRecorder = $messageRecorder;
    }

    /**
     * @param CreateIdTokenCommand $command
     */
    public function handle(CreateIdTokenCommand $command)
    {
        $idToken = $this->idTokenRepository->create(
            $command->getClient(),
            $command->getUserAccount(),
            $command->getRedirectUri(),
            $command->getParameters(),
            $command->getMetadatas(),
            $command->getScopes(),
            $command->getExpiresAt(),
            []
        );
        if (null !== $command->getDataTransporter()) {
            $data = $command->getDataTransporter();
            $data($idToken);
        }
        $event = IdTokenCreatedEvent::create($idToken);
        $this->messageRecorder->record($event);
    }
}
