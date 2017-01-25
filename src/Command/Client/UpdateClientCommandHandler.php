<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\Client;

use OAuth2\Client\Rule\RuleManager;
use OAuth2\Model\Client\ClientRepositoryInterface;

final class UpdateClientCommandHandler
{
    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var RuleManager
     */
    private $ruleManager;

    /**
     * UpdateClientCommandHandler constructor.
     *
     * @param ClientRepositoryInterface $clientRepository
     * @param RuleManager      $ruleManager
     */
    public function __construct(ClientRepositoryInterface $clientRepository, RuleManager $ruleManager)
    {
        $this->clientRepository = $clientRepository;
        $this->ruleManager = $ruleManager;
    }

    /**
     * @param UpdateClientCommand $command
     */
    public function handle(UpdateClientCommand $command)
    {
        $parameters = $command->getParameters();
        $client = $command->getClient();
        $validated_parameters = $this->ruleManager->handle($parameters, $client->getResourceOwnerId());
        $validated_parameters['client_id'] = $client->getId()->getValue();
        if (true === $client->has('client_id_issued_at')) {
            $validated_parameters['client_id_issued_at'] = $client->get('client_id_issued_at');
        }
        $client = $client->withParameters($validated_parameters);
        $this->clientRepository->save($client);
        $callback = $command->getDataTransporter();
        $callback($client);
    }
}
