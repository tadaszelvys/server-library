<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Model\Event\Event;
use OAuth2\Model\Event\EventId;
use OAuth2\Model\Event\EventStoreInterface;

final class EventStore implements EventStoreInterface
{
    /**
     * @var Event[]
     */
    private $events = [];

    /**
     * {@inheritdoc}
     */
    public function find(EventId $eventId)
    {
        return array_key_exists($eventId->getValue(), $this->events) ? $this->events[$eventId->getValue()] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function save(Event $event)
    {
        $this->events[$event->getEventId()->getValue()] = $event;
    }

    /**
     * {@inheritdoc}
     */
    public function all()
    {
        return $this->events;
    }
}
