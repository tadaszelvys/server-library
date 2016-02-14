<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use Assert\Assertion;
use Jose\Object\JWKSetInterface;
use OAuth2\ResourceServer\ResourceServer as Base;

class ResourceServer extends Base
{
    private $allowed_ip_addresses = [];

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
    public function isIpAddressAllowed($ip)
    {
        return in_array($ip, $this->getAllowedIpAddresses());
    }

    /**
     * @param string[] $allowed_ip_addresses
     */
    public function setAllowedIpAddresses(array $allowed_ip_addresses)
    {
        $this->allowed_ip_addresses = $allowed_ip_addresses;
    }

    /**
     * @param string $server_name
     */
    public function setServerName($server_name)
    {
        Assertion::string($server_name);
        $this->server_name = $server_name;
    }

    /**
     * @param \Jose\Object\JWKSetInterface $public_key_encryption_keyset
     */
    public function setPublicKeyEncryptionKey(JWKSetInterface $public_key_encryption_keyset)
    {
        $this->public_key_encryption_keyset = $public_key_encryption_keyset;
    }
}
