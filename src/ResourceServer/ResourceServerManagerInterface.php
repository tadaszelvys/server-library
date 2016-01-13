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

use OAuth2\Client\ClientManagerInterface;

/**
 * This interface is for resource servers.
 */
interface ResourceServerManagerInterface extends ClientManagerInterface
{
    /**
     * @param string[] $trusted_proxies
     */
    public function setTrustedProxies(array $trusted_proxies);

    /**
     * @return string[]
     */
    public function getTrustedProxies();
}
