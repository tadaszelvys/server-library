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

namespace OAuth2\Model\Event;

use Ramsey\Uuid\Uuid;

abstract class Event implements \JsonSerializable
{
    /**
     * @var EventId
     */
    private $eventId;

    /**
     * @var float
     */
    private $recordedOn;

    /**
     * Event constructor.
     */
    protected function __construct()
    {
        $this->recordedOn = \DateTimeImmutable::createFromFormat('U.u', (string) microtime(true));
        $this->eventId = EventId::create(Uuid::uuid4()->toString());
    }

    /**
     * @return EventId
     */
    public function getEventId(): EventId
    {
        return $this->eventId;
    }

    /**
     * @return mixed
     */
    abstract public function getPayload();

    /**
     * @return \DateTimeImmutable
     */
    public function getRecordedOn(): \DateTimeImmutable
    {
        return $this->recordedOn;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        return [
            'id'          => $this->getEventId()->getValue(),
            'type'        => get_class($this),
            'recorded_on' => (float) $this->getRecordedOn()->format('U.u'),
            'payload'     => $this->getPayload(),
        ];
    }
}
