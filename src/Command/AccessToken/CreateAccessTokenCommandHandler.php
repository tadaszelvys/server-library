<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\AccessToken;

use OAuth2\Event\AccessToken\AccessTokenCreatedEvent;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class CreateAccessTokenCommandHandler
{
    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var RecordsMessages
     */
    private $messageRecorder;

    /**
     * CreateClientCommandHandler constructor.
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     * @param RecordsMessages $messageRecorder
     */
    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository, RecordsMessages $messageRecorder)
    {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->messageRecorder = $messageRecorder;
    }

    /**
     * @param CreateAccessTokenCommand $command
     */
    public function handle(CreateAccessTokenCommand $command)
    {
        $accessToken = $this->accessTokenRepository->create(
            $command->getResourceOwner(),
            $command->getClient(),
            $command->getParameters(),
            $command->getMetadatas(),
            $command->getScopes(),
            $command->getExpiresAt()
        );
        $this->accessTokenRepository->save($accessToken);
        $event = AccessTokenCreatedEvent::create($accessToken);
        $this->messageRecorder->record($event);
    }
}
