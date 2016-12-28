<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\Client;

use OAuth2\Event\Client\ClientDeletedEvent;
use OAuth2\Model\Client\ClientRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class DeleteClientCommandHandler
{
    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var ClientRepositoryInterface
     */
    private $messageRecorder;

    /**
     * DeleteClientCommandHandler constructor.
     *
     * @param ClientRepositoryInterface $clientRepository
     * @param RecordsMessages           $messageRecorder
     */
    public function __construct(ClientRepositoryInterface $clientRepository, RecordsMessages $messageRecorder)
    {
        $this->clientRepository = $clientRepository;
        $this->messageRecorder = $messageRecorder;
    }

    /**
     * @param DeleteClientCommand $command
     */
    public function handle(DeleteClientCommand $command)
    {
        $client = $command->getClient();
        $this->clientRepository->delete($client);

        $event = ClientDeletedEvent::create($client);
        $this->messageRecorder->record($event);
    }
}
