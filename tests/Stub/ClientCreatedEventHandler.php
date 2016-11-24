<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Event\Client\ClientCreatedEvent;
use OAuth2\Model\Event\EventStoreInterface;

final class ClientCreatedEventHandler
{
    /**
     * @var EventStoreInterface
     */
    private $eventStore;

    /**
     * ClientCreatedEventHandler constructor.
     * @param EventStoreInterface $eventStore
     */
    public function __construct(EventStoreInterface $eventStore)
    {
        $this->eventStore = $eventStore;
    }

    /**
     * @param ClientCreatedEvent $event
     */
    public function handle(ClientCreatedEvent $event)
    {
        $this->eventStore->save($event);
    }
}
