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

use SimpleBus\Message\CallableResolver\CallableMap;
use SimpleBus\Message\Handler\Resolver\NameBasedMessageHandlerResolver;
use SimpleBus\Message\Name\ClassBasedNameResolver;

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
