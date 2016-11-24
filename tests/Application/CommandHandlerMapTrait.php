<?php

namespace OAuth2\Test\Application;

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
                ],
                $this->getServiceLocatorAwareCallableResolver()
            );
        }

        return $this->commandHandlerMap;
    }
}
