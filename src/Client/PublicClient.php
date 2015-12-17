<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client;

/**
 * This interface is for registered clients.
 * These clients have an ID and the server can get the client details.
 *
 * @see http://tools.ietf.org/html/rfc6749#section-2.1
 */
class PublicClient extends RegisteredClient implements PublicClientInterface
{
    /**
     * PublicClient constructor.
     */
    public function __construct()
    {
        parent::__construct();
        $this->setType('public_client');
    }
}
