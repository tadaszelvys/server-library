<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\ResourceServer;

interface ResourceServerRepositoryInterface
{
    /**
     * @param ResourceServer $resourceServer
     */
    public function save(ResourceServer $resourceServer);

    /**
     * This function deletes a resource server.
     *
     * @param ResourceServer $resourceServer The resource server to delete
     */
    public function delete(ResourceServer $resourceServer);

    /**
     * @param ResourceServerId $resourceServer The resource server
     *
     * @return ResourceServerId|null Return the resource server or null if the argument is not a valid resource server ID
     */
    public function find(ResourceServerId $resourceServer);
}
