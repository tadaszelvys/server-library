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

namespace OAuth2\Command\AuthCode;

use OAuth2\Event\AuthCode\AuthCodeRevokedEvent;
use OAuth2\Model\AuthCode\AuthCodeRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class RevokeAuthCodeCommandHandler
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
     *
     * @param AuthCodeRepositoryInterface $authCodeRepository
     * @param RecordsMessages             $messageRecorder
     */
    public function __construct(AuthCodeRepositoryInterface $authCodeRepository, RecordsMessages $messageRecorder)
    {
        $this->authCodeRepository = $authCodeRepository;
        $this->messageRecorder = $messageRecorder;
    }

    /**
     * @param RevokeAuthCodeCommand $command
     */
    public function handle(RevokeAuthCodeCommand $command)
    {
        $authCode = $command->getAuthCode();
        $this->authCodeRepository->revoke($authCode);
        $event = AuthCodeRevokedEvent::create($authCode);
        $this->messageRecorder->record($event);
    }
}
