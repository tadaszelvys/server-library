<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

/**
 * This interface is for unregistered clients.
 * These clients have an ID, but the server can get the client details.
 * Us this client type with caution!
 *
 * @see http://tools.ietf.org/html/rfc6749#section-2.1
 */
class UnregisteredClient extends Client
{
    /**
     * UnregisteredClient constructor.
     */
    public function __construct()
    {
        parent::__construct();
        $this->setType('unregistered_client');
    }
}
