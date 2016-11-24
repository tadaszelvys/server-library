<?php

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
