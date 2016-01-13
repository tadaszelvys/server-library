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
 * This interface is for resource servers.
 */
interface ResourceServerInterface extends ClientInterface
{
    /**
     * @param string[] $allowed_ip_address
     */
    public function setAllowedIpAddresses(array $allowed_ip_address);

    /**
     * @return string[]
     */
    public function getAllowedIpAddresses();

    /**
     * @param string $ip
     *
     * @return bool
     */
    public function isIpAddressAllowed($ip);

    /**
     * @return string
     */
    public function getServerName();

    /**
     * @param string $server_name
     */
    public function setServerName($server_name);
}
