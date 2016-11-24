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

use OAuth2\Event\AccessToken\AccessTokenRevokedEvent;
use OAuth2\Model\AccessToken\AccessTokenRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class RevokeAccessTokenCommandHandler
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
     * @param RevokeAccessTokenCommand $command
     */
    public function handle(RevokeAccessTokenCommand $command)
    {
        $accessToken = $command->getAccessToken();
        $this->accessTokenRepository->revoke($accessToken);
        $event = AccessTokenRevokedEvent::create($accessToken);
        $this->messageRecorder->record($event);
    }
}
