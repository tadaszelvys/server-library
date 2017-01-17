<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub\Event;

use OAuth2\Event\RefreshToken\RefreshTokenRevokedEvent;
use OAuth2\Model\Event\EventStoreInterface;

final class RefreshTokenRevokedEventHandler
{
    /**
     * @var EventStoreInterface
     */
    private $eventStore;

    /**
     * ClientCreatedEventHandler constructor.
     *
     * @param EventStoreInterface $eventStore
     */
    public function __construct(EventStoreInterface $eventStore)
    {
        $this->eventStore = $eventStore;
    }

    /**
     * @param RefreshTokenRevokedEvent $event
     */
    public function handle(RefreshTokenRevokedEvent $event)
    {
        $this->eventStore->save($event);
    }
}
