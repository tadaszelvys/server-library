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
 * This interface is for resource servers.
 */
interface ResourceServerInterface extends ConfidentialClientInterface
{
    /**
     * @return string[]
     */
    public function getAllowedIpAddresses();

    /**
     * @return string
     */
    public function getServerName();
}
