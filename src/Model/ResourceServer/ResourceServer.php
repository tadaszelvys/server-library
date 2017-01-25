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

namespace OAuth2\Model\ResourceServer;

use SimpleBus\Message\Recorder\ContainsRecordedMessages;
use SimpleBus\Message\Recorder\PrivateMessageRecorderCapabilities;

final class ResourceServer implements ContainsRecordedMessages
{
    use PrivateMessageRecorderCapabilities;

    /**
     * @var ResourceServerId
     */
    private $resourceServerId;

    /**
     * ResourceServer constructor.
     *
     * @param ResourceServerId $resourceServerId
     */
    private function __construct(ResourceServerId $resourceServerId)
    {
        $this->resourceServerId = $resourceServerId;

        //$event = ResourceServerCreatedEvent::create($resourceServerId);
        //$this->record($event);
    }

    /**
     * @param ResourceServerId $resourceServerId
     *
     * @return ResourceServer
     */
    public static function create(ResourceServerId $resourceServerId): self
    {
        return new self($resourceServerId);
    }

    /**
     * @return ResourceServerId
     */
    public function getId(): ResourceServerId
    {
        return $this->resourceServerId;
    }
}
