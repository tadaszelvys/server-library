<?php

namespace OAuth2\Test\Application;

use OAuth2\Test\Stub\ClientCreatedEventHandler;
use OAuth2\Test\Stub\ClientDeletedEventHandler;
use OAuth2\Test\Stub\ClientUpdatedEventHandler;
use OAuth2\Model\Event\EventStoreInterface;

trait ClientEventHandlerTrait
{
    abstract public function getEventStore(): EventStoreInterface;

    /**
     * @var null|ClientCreatedEventHandler
     */
    private $clientCreatedEventHandler = null;

    /**
     * @return ClientCreatedEventHandler
     */
    public function getClientCreatedEventHandler(): ClientCreatedEventHandler
    {
        if (null === $this->clientCreatedEventHandler) {
            $this->clientCreatedEventHandler = new ClientCreatedEventHandler(
                $this->getEventStore()
            );
        }

        return $this->clientCreatedEventHandler;
    }

    /**
     * @var null|ClientDeletedEventHandler
     */
    private $clientDeletedEventHandler = null;

    /**
     * @return ClientDeletedEventHandler
     */
    public function getClientDeletedEventHandler(): ClientDeletedEventHandler
    {
        if (null === $this->clientDeletedEventHandler) {
            $this->clientDeletedEventHandler = new ClientDeletedEventHandler(
                $this->getEventStore()
            );
        }

        return $this->clientDeletedEventHandler;
    }

    /**
     * @var null|ClientUpdatedEventHandler
     */
    private $clientUpdatedEventHandler = null;

    /**
     * @return ClientUpdatedEventHandler
     */
    public function getClientUpdatedEventHandler(): ClientUpdatedEventHandler
    {
        if (null === $this->clientUpdatedEventHandler) {
            $this->clientUpdatedEventHandler = new ClientUpdatedEventHandler(
                $this->getEventStore()
            );
        }

        return $this->clientUpdatedEventHandler;
    }
}
