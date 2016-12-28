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

use SimpleBus\Message\CallableResolver\CallableCollection;
use SimpleBus\Message\Name\ClassBasedNameResolver;
use SimpleBus\Message\Subscriber\Resolver\NameBasedMessageSubscriberResolver;

trait EventHandlerResolverTrait
{
    abstract public function getEventHandlerMap(): CallableCollection;

    /**
     * @var null|NameBasedMessageSubscriberResolver
     */
    private $eventHandlerResolver = null;

    /**
     * @return NameBasedMessageSubscriberResolver
     */
    public function getEventHandlerResolver(): NameBasedMessageSubscriberResolver
    {
        if (null === $this->eventHandlerResolver) {
            $this->eventHandlerResolver = new NameBasedMessageSubscriberResolver(
                new ClassBasedNameResolver(),
                $this->getEventHandlerMap()
            );
        }

        return $this->eventHandlerResolver;
    }
}
