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
use SimpleBus\Message\Handler\DelegatesToMessageHandlerMiddleware;
use SimpleBus\Message\Handler\Resolver\NameBasedMessageHandlerResolver;
use SimpleBus\Message\Recorder\HandlesRecordedMessagesMiddleware;
use SimpleBus\Message\Recorder\PublicMessageRecorder;

trait CommandBusTrait
{
    abstract public function getCommandHandlerResolver(): NameBasedMessageHandlerResolver;

    abstract public function getPublicMessageRecorder(): PublicMessageRecorder;

    abstract public function getEventBus(): MessageBusSupportingMiddleware;

    /**
     * @var null|MessageBusSupportingMiddleware
     */
    private $commandBus = null;

    /**
     * @return MessageBusSupportingMiddleware
     */
    public function getCommandBus(): MessageBusSupportingMiddleware
    {
        if (null === $this->commandBus) {
            $this->commandBus = new MessageBusSupportingMiddleware();
            $this->commandBus->appendMiddleware(new HandlesRecordedMessagesMiddleware(
                $this->getPublicMessageRecorder(),
                $this->getEventBus()
            ));
            $this->commandBus->appendMiddleware(new FinishesHandlingMessageBeforeHandlingNext());
            $this->commandBus->appendMiddleware(new DelegatesToMessageHandlerMiddleware(
                $this->getCommandHandlerResolver()
            ));
        }

        return $this->commandBus;
    }
}
