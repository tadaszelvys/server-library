<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\RefreshToken;

use OAuth2\Event\RefreshToken\RefreshTokenRevokedEvent;
use OAuth2\Model\RefreshToken\RefreshTokenRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class RevokeRefreshTokenCommandHandler
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
     * CreateClientCommandHandler constructor.
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
     * @param RevokeRefreshTokenCommand $command
     */
    public function handle(RevokeRefreshTokenCommand $command)
    {
        $refreshToken = $command->getRefreshToken();
        $this->refreshTokenRepository->revoke($refreshToken);
        $event = RefreshTokenRevokedEvent::create($refreshToken);
        $this->messageRecorder->record($event);
    }
}
