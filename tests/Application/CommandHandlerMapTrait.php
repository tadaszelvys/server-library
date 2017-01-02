<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Application;

use OAuth2\Command\AccessToken\RevokeAccessTokenCommand;
use OAuth2\Command\AccessToken\RevokeAccessTokenCommandHandler;
use OAuth2\Command\Client\CreateClientCommand;
use OAuth2\Command\Client\CreateClientCommandHandler;
use OAuth2\Command\Client\DeleteClientCommand;
use OAuth2\Command\Client\DeleteClientCommandHandler;
use OAuth2\Command\Client\UpdateClientCommand;
use OAuth2\Command\Client\UpdateClientCommandHandler;
use SimpleBus\Message\CallableResolver\CallableMap;
use SimpleBus\Message\CallableResolver\ServiceLocatorAwareCallableResolver;

trait CommandHandlerMapTrait
{
    abstract public function getServiceLocatorAwareCallableResolver(): ServiceLocatorAwareCallableResolver;

    /**
     * @var null|CallableMap
     */
    private $commandHandlerMap = null;

    /**
     * @return CallableMap
     */
    public function getCommandHandlerMap(): CallableMap
    {
        if (null === $this->commandHandlerMap) {
            $this->commandHandlerMap = new CallableMap(
                [
                    CreateClientCommand::class => CreateClientCommandHandler::class,
                    DeleteClientCommand::class => DeleteClientCommandHandler::class,
                    UpdateClientCommand::class => UpdateClientCommandHandler::class,
                    RevokeAccessTokenCommand::class => RevokeAccessTokenCommandHandler::class,
                ],
                $this->getServiceLocatorAwareCallableResolver()
            );
        }

        return $this->commandHandlerMap;
    }
}
