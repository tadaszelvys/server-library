<?php

namespace OAuth2\Test\Application;

use SimpleBus\Message\CallableResolver\CallableMap;
use SimpleBus\Message\Name\ClassBasedNameResolver;
use SimpleBus\Message\Handler\Resolver\NameBasedMessageHandlerResolver;

trait CommandHandlerResolverTrait
{
    abstract public function getCommandHandlerMap(): CallableMap;

    /**
     * @var null|NameBasedMessageHandlerResolver
     */
    private $commandHandlerResolver = null;

    /**
     * @return NameBasedMessageHandlerResolver
     */
    public function getCommandHandlerResolver(): NameBasedMessageHandlerResolver
    {
        if (null === $this->commandHandlerResolver) {
            $this->commandHandlerResolver = new NameBasedMessageHandlerResolver(
                new ClassBasedNameResolver(),
                $this->getCommandHandlerMap()
            );
        }

        return $this->commandHandlerResolver;
    }
}
