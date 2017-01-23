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

use OAuth2\Client\Rule\RuleManagerInterface;
use OAuth2\Model\Client\ClientRepositoryInterface;

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
     * CreateClientCommandHandler constructor.
     *
     * @param ClientRepositoryInterface $clientRepository
     * @param RuleManagerInterface      $ruleManager
     */
    public function __construct(ClientRepositoryInterface $clientRepository, RuleManagerInterface $ruleManager)
    {
        $this->clientRepository = $clientRepository;
        $this->ruleManager = $ruleManager;
    }

    /**
     * @param CreateClientCommand $command
     */
    public function handle(CreateClientCommand $command)
    {
        $parameters = $command->getParameters();
        $userAccountId = $command->getUserAccountId();
        $validated_parameters = $this->ruleManager->handle($parameters, $userAccountId);
        $client = $this->clientRepository->create(
            $command->getUserAccountId(),
            $validated_parameters
        );
        $this->clientRepository->save($client);
        $callback = $command->getDataTransporter();
        $callback($client);
    }
}
