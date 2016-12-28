<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\Event;

use Ramsey\Uuid\Uuid;

abstract class Event implements \JsonSerializable
{
    /**
     * @var EventId
     */
    private $eventId;

    /**
     * @var \JsonSerializable
     */
    private $payload;

    /**
     * @var float
     */
    private $recorded_on;

    /**
     * ClientCreatedEvent constructor.
     *
     * @param \JsonSerializable $payload
     */
    protected function __construct(\JsonSerializable $payload)
    {
        $recorded_on = \DateTimeImmutable::createFromFormat('U.u', microtime(true));
        $eventId = EventId::create(Uuid::uuid4()->toString());
        $this->eventId = $eventId;
        $this->payload = $payload;
        $this->recorded_on = $recorded_on;
    }

    /**
     * @param array $json
     *
     * @return \JsonSerializable
     */
    abstract protected static function createPayloadFromJson(array $json): \JsonSerializable;

    /**
     * @return EventId
     */
    public function getEventId(): EventId
    {
        return $this->eventId;
    }

    /**
     * @return \JsonSerializable
     */
    public function getPayload(): \JsonSerializable
    {
        return $this->payload;
    }

    /**
     * @return \DateTimeImmutable
     */
    public function getRecordedOn(): \DateTimeImmutable
    {
        return $this->recorded_on;
    }
}
