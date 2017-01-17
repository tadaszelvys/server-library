<?php declare(strict_types=1);

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
use OAuth2\Event\Client\ClientUpdatedEvent;
use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientRepositoryInterface;
use SimpleBus\Message\Recorder\RecordsMessages;

final class UpdateClientCommandHandler
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
     * UpdateClientCommandHandler constructor.
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
     * @param UpdateClientCommand $command
     */
    public function handle(UpdateClientCommand $command)
    {
        $parameters = $command->getParameters();
        $client = $command->getClient();
        $validated_parameters = $this->ruleManager->handle($parameters, $client->getResourceOwnerPublic());
        $validated_parameters['client_id'] = $client->getId()->getValue();
        if (true === $client->has('client_id_issued_at')) {
            $validated_parameters['client_id_issued_at'] = $client->get('client_id_issued_at');
        }
        $client = Client::create(
            $client->getId(),
            $validated_parameters,
            $client->getResourceOwnerPublic()
        );
        $this->clientRepository->save($client);
        $event = ClientUpdatedEvent::create($client);
        $this->messageRecorder->record($event);
        $callback = $command->getDataTransporter();
        $callback($client);
    }
}
