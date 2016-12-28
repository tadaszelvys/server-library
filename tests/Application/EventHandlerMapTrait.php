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

use OAuth2\Event\Client\ClientCreatedEvent;
use OAuth2\Event\Client\ClientDeletedEvent;
use OAuth2\Event\Client\ClientUpdatedEvent;
use OAuth2\Test\Stub\ClientCreatedEventHandler;
use OAuth2\Test\Stub\ClientDeletedEventHandler;
use OAuth2\Test\Stub\ClientUpdatedEventHandler;
use SimpleBus\Message\CallableResolver\CallableCollection;
use SimpleBus\Message\CallableResolver\ServiceLocatorAwareCallableResolver;

trait EventHandlerMapTrait
{
    abstract public function getServiceLocatorAwareCallableResolver(): ServiceLocatorAwareCallableResolver;

    /**
     * @var null|CallableCollection
     */
    private $eventHandlerMap = null;

    /**
     * @return CallableCollection
     */
    public function getEventHandlerMap(): CallableCollection
    {
        if (null === $this->eventHandlerMap) {
            $this->eventHandlerMap = new CallableCollection(
                [
                    ClientCreatedEvent::class => [
                        ClientCreatedEventHandler::class,
                    ],
                    ClientDeletedEvent::class => [
                        ClientDeletedEventHandler::class,
                    ],
                    ClientUpdatedEvent::class => [
                        ClientUpdatedEventHandler::class,
                    ],
                ],
                $this->getServiceLocatorAwareCallableResolver()
            );
        }

        return $this->eventHandlerMap;
    }
}
