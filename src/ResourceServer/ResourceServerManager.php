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

/**
 * Class ResourceServerManager
 * @package OAuth2\ResourceServer
 */
abstract class ResourceServerManager implements ResourceServerManagerInterface
{
    /**
     * @var string[]
     */
    private $trusted_proxies = [];

    /**
     * {@inheritdoc}
     */
    public function getTrustedProxies()
    {
        return $this->trusted_proxies;
    }

    /**
     * {@inheritdoc}
     */
    public function setTrustedProxies(array $trusted_proxies)
    {
        $this->trusted_proxies = $trusted_proxies;
    }
}
