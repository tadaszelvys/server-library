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

use OAuth2\Command\Client\CreateClientCommandHandler;
use OAuth2\Command\Client\DeleteClientCommandHandler;
use OAuth2\Command\Client\UpdateClientCommandHandler;
use OAuth2\Test\Stub\ClientCreatedEventHandler;
use OAuth2\Test\Stub\ClientDeletedEventHandler;
use OAuth2\Test\Stub\ClientUpdatedEventHandler;
use OAuth2\Test\Stub\Container;

trait ContainerTrait
{
    abstract public function getCreateClientCommandHandler(): CreateClientCommandHandler;

    abstract public function getClientCreatedEventHandler(): ClientCreatedEventHandler;

    abstract public function getDeleteClientCommandHandler(): DeleteClientCommandHandler;

    abstract public function getClientDeletedEventHandler(): ClientDeletedEventHandler;

    abstract public function getUpdateClientCommandHandler(): UpdateClientCommandHandler;

    abstract public function getClientUpdatedEventHandler(): ClientUpdatedEventHandler;

    /**
     * @var null|Container
     */
    private $container = null;

    /**
     * @return Container
     */
    public function getContainer(): Container
    {
        if (null === $this->container) {
            $this->container = new Container();

            $this->container->add($this->getCreateClientCommandHandler());
            $this->container->add($this->getDeleteClientCommandHandler());
            $this->container->add($this->getUpdateClientCommandHandler());
            $this->container->add($this->getClientCreatedEventHandler());
            $this->container->add($this->getClientDeletedEventHandler());
            $this->container->add($this->getClientUpdatedEventHandler());
        }

        return $this->container;
    }
}
