<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\ResourceServer;

interface ResourceServerRepositoryInterface
{
    /**
     * @return ResourceServer
     */
    public function create(): ResourceServer;

    /**
     * @param ResourceServer $resourceServer
     */
    public function save(ResourceServer $resourceServer);

    /**
     * @param ResourceServerId $resourceServerId
     *
     * @return bool
     */
    public function has(ResourceServerId $resourceServerId): bool;

    /**
     * This function deletes a resource server.
     *
     * @param ResourceServerId $resourceServerId The resource server to delete
     */
    public function delete(ResourceServerId $resourceServerId);

    /**
     * @param ResourceServerId $resourceServer The resource server
     *
     * @return ResourceServer|null Return the resource server or null if the argument is not a valid resource server ID
     */
    public function find(ResourceServerId $resourceServer);
}
