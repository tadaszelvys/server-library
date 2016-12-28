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

use OAuth2\Test\Stub\ClientRepository;

trait ClientRepositoryTrait
{
    /**
     * @var null|ClientRepository
     */
    private $clientRepository = null;

    /**
     * @return ClientRepository
     */
    public function getClientRepository(): ClientRepository
    {
        if (null === $this->clientRepository) {
            $this->clientRepository = new ClientRepository();
        }

        return $this->clientRepository;
    }
}
