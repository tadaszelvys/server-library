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

use OAuth2\Event\AccessToken\AccessTokenRevokedEvent;
use OAuth2\Event\Client\ClientCreatedEvent;
use OAuth2\Event\Client\ClientDeletedEvent;
use OAuth2\Event\Client\ClientUpdatedEvent;
use OAuth2\Test\Stub\Event\AccessTokenRevokedEventHandler;
use OAuth2\Test\Stub\Event\ClientCreatedEventHandler;
use OAuth2\Test\Stub\Event\ClientDeletedEventHandler;
use OAuth2\Test\Stub\Event\ClientUpdatedEventHandler;
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
                    AccessTokenRevokedEvent::class => [AccessTokenRevokedEventHandler::class],
                    ClientCreatedEvent::class => [ClientCreatedEventHandler::class],
                    ClientDeletedEvent::class => [ClientDeletedEventHandler::class],
                    ClientUpdatedEvent::class => [ClientUpdatedEventHandler::class],
                ],
                $this->getServiceLocatorAwareCallableResolver()
            );
        }

        return $this->eventHandlerMap;
    }
}
