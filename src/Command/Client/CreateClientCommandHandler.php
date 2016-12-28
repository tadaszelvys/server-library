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

use OAuth2\Client\Rule\RuleManagerInterface;
use OAuth2\Event\Client\ClientCreatedEvent;
use OAuth2\Model\Client\ClientRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class CreateClientCommandHandler
{
    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var RuleManagerInterface
     */
    private $ruleManager;

    /**
     * @var RecordsMessages
     */
    private $messageRecorder;

    /**
     * CreateClientCommandHandler constructor.
     *
     * @param ClientRepositoryInterface $clientRepository
     * @param RuleManagerInterface      $ruleManager
     * @param RecordsMessages           $messageRecorder
     */
    public function __construct(ClientRepositoryInterface $clientRepository, RuleManagerInterface $ruleManager, RecordsMessages $messageRecorder)
    {
        $this->clientRepository = $clientRepository;
        $this->ruleManager = $ruleManager;
        $this->messageRecorder = $messageRecorder;
    }

    /**
     * @param CreateClientCommand $command
     */
    public function handle(CreateClientCommand $command)
    {
        $parameters = $command->getParameters();
        $userAccount = $command->getUserAccount();
        $validated_parameters = $this->ruleManager->handle($parameters, $userAccount);
        $client = $this->clientRepository->create(
            $command->getUserAccount(),
            $validated_parameters
        );
        $this->clientRepository->save($client);
        $event = ClientCreatedEvent::create($client);
        $this->messageRecorder->record($event);
        $callback = $command->getCallback();
        $callback($client);
    }
}
