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
use OAuth2\Client\Client;

/**
 * Class ResourceServer.
 */
class ResourceServer extends Client implements ResourceServerInterface
{
    /**
     * @var string
     */
    protected $server_name;

    /**
     * @var string[]
     */
    protected $allowed_ip_addresses = [];

    /**
     * {@inheritdoc}
     */
    public function getServerName()
    {
        return $this->server_name;
    }

    /**
     * {@inheritdoc}
     */
    public function getAllowedIpAddresses()
    {
        return $this->allowed_ip_addresses;
    }

    /**
     * {@inheritdoc}
     */
    public function isAllowedGrantType($grant_type)
    {
        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function getAllowedGrantTypes()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function setAllowedGrantTypes(array $grant_types)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function addAllowedGrantType($grant_type)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function removeAllowedGrantType($grant_type)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return 'resource_server';
    }

    /**
     * {@inheritdoc}
     */
    public function setType($type)
    {
        //Nothing to do
    }

    /**
     * {@inheritdoc}
     */
    public function isIpAddressAllowed($ip)
    {
        return in_array($ip, $this->getAllowedIpAddresses());
    }

    /**
     * {@inheritdoc}
     */
    public function setAllowedIpAddresses(array $allowed_ip_addresses)
    {
        $this->allowed_ip_addresses = $allowed_ip_addresses;
    }

    /**
     * {@inheritdoc}
     */
    public function setServerName($server_name)
    {
        $this->server_name = $server_name;
    }
}
