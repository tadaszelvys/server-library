<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\ResourceServer;

use OAuth2\Client\ClientInterface;

/**
 * Class ResourceServerManager.
 */
abstract class ResourceServerManager implements ResourceServerManagerInterface
{
    /**
     * {@inheritdoc}
     */
    public function isClientSupported(ClientInterface $client)
    {
        return $client instanceof ResourceServerInterface;
    }
}
