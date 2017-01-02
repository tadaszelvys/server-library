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

use OAuth2\Model\Event\EventStoreInterface;
use OAuth2\Test\Stub\Event\AccessTokenRevokedEventHandler;

trait AccessTokenEventHandlerTrait
{
    abstract public function getEventStore(): EventStoreInterface;

    /**
     * @var null|AccessTokenRevokedEventHandler
     */
    private $accessTokenRevokedEventHandler = null;

    /**
     * @return AccessTokenRevokedEventHandler
     */
    public function getAccessTokenRevokedEventHandler(): AccessTokenRevokedEventHandler
    {
        if (null === $this->accessTokenRevokedEventHandler) {
            $this->accessTokenRevokedEventHandler = new AccessTokenRevokedEventHandler(
                $this->getEventStore()
            );
        }

        return $this->accessTokenRevokedEventHandler;
    }
}
