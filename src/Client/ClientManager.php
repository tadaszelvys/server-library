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

abstract class ClientManager implements ClientManagerInterface
{
    /**
     * {@inheritdoc}
     */
    public function createClient()
    {
        $client = new Client();
        $client->set('client_id_issued_at', time());

        return $client;
    }
}
