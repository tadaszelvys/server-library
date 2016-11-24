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

use OAuth2\Event\Client\ClientDeletedEvent;
use OAuth2\Model\Event\EventStoreInterface;

final class ClientDeletedEventHandler
{
    /**
     * @var EventStoreInterface
     */
    private $eventStore;

    /**
     * ClientDeletedEventHandler constructor.
     * @param EventStoreInterface $eventStore
     */
    public function __construct(EventStoreInterface $eventStore)
    {
        $this->eventStore = $eventStore;
    }

    /**
     * @param ClientDeletedEvent $event
     */
    public function handle(ClientDeletedEvent $event)
    {
        $this->eventStore->save($event);
    }
}
