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

use SimpleBus\Message\Bus\Middleware\FinishesHandlingMessageBeforeHandlingNext;
use SimpleBus\Message\Bus\Middleware\MessageBusSupportingMiddleware;
use SimpleBus\Message\Subscriber\NotifiesMessageSubscribersMiddleware;
use SimpleBus\Message\Subscriber\Resolver\NameBasedMessageSubscriberResolver;

trait EventBusTrait
{
    abstract public function getEventHandlerResolver(): NameBasedMessageSubscriberResolver;

    /**
     * @var null|MessageBusSupportingMiddleware
     */
    private $eventBus = null;

    /**
     * @return MessageBusSupportingMiddleware
     */
    public function getEventBus(): MessageBusSupportingMiddleware
    {
        if (null === $this->eventBus) {
            $this->eventBus = new MessageBusSupportingMiddleware();
            $this->eventBus->appendMiddleware(new FinishesHandlingMessageBeforeHandlingNext());
            $this->eventBus->appendMiddleware(new NotifiesMessageSubscribersMiddleware(
                $this->getEventHandlerResolver()
            ));
        }

        return $this->eventBus;
    }
}
