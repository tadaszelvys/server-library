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

use OAuth2\Client\ClientInterface;
use OAuth2\ResourceServer\ResourceServerManager as Base;
use OAuth2\Util\IpAddress;
use Psr\Http\Message\ServerRequestInterface;

class ResourceServerManager extends Base
{
    /**
     * @var \OAuth2\ResourceServer\ResourceServer[]
     */
    private $resource_servers = [];

    /**
     * @var string[]
     */
    private $trusted_proxies = [];

    /**
     * ResourceServerManager constructor.
     */
    public function __construct()
    {
        $this->setTrustedProxies(['127.0.0.1']);
    }

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

    /**
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        return array_key_exists($client_id, $this->resource_servers) ? $this->resource_servers[$client_id] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function createResourceServers()
    {
        $server1 = new ResourceServer();
        $server1->setServerName('SERVER1');
        $server1->setAllowedIpAddresses(['127.0.0.1']);
        $server1->setPublicId('SERVER1');

        $server2 = new ResourceServer();
        $server2->setServerName('SERVER2');
        $server2->setAllowedIpAddresses(['192.168.1.12']);
        $server2->setPublicId('SERVER2');

        $this->resource_servers['SERVER1'] = $server1;
        $this->resource_servers['SERVER2'] = $server2;
    }

    /**
     * {@inheritdoc}
     */
    public function getSchemesParameters()
    {
        return [];
    }

    /**
     * {@inheritdoc}
     */
    public function findClient(ServerRequestInterface $request, &$client_credentials = null)
    {
        if (!$request->hasHeader('X-OAuth2-Resource-Server')) {
            return;
        }

        $server_name = $request->getHeader('X-OAuth2-Resource-Server');
        if (1 !== count($server_name)) {
            return;
        }

        return $this->getClient($server_name[0]);
    }

    /**
     * {@inheritdoc}
     */
    public function isClientAuthenticated(ClientInterface $client, $client_credentials, ServerRequestInterface $request, &$reason = null)
    {
        $ip = IpAddress::getClientIp($request, $this->getTrustedProxies());

        return $client->isIpAddressAllowed($ip);
    }
    /**
     * {@inheritdoc}
     */
    public function getSupportedAuthenticationMethods()
    {
        return ['resource_server_custom_auth'];
    }
}
