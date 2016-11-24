<?php

namespace OAuth2\Test\Application;

use OAuth2\Model\Event\EventStoreInterface;
use OAuth2\Test\Stub\EventStore;

trait EventStoreTrait
{
    /**
     * @var null|EventStoreInterface
     */
    private $eventStore = null;

    /**
     * @return EventStoreInterface
     */
    public function getEventStore(): EventStoreInterface
    {
        if (null === $this->eventStore) {
            $this->eventStore = new EventStore();
        }

        return $this->eventStore;
    }
}
