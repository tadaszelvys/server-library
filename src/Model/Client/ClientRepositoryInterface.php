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

namespace OAuth2\Model\Client;

use OAuth2\Model\UserAccount\UserAccountId;

interface ClientRepositoryInterface
{
    /**
     * @param UserAccountId $userAccountId
     * @param array         $metadatas
     *
     * @return Client
     */
    public function create(UserAccountId $userAccountId, array $metadatas);

    /**
     * @param ClientId $clientId
     * @return bool
     */
    public function has(ClientId $clientId): bool;

    /**
     * Get a client using its Id.
     *
     * @param ClientId $clientId
     *
     * @return null|Client Return the client object or null if no client is found.
     */
    public function find(ClientId $clientId);

    /**
     * @return Client[]
     */
    public function findAll();

    /**
     * Save the client.
     *
     * @param Client $client
     */
    public function save(Client $client);

    /**
     * Delete the client.
     *
     * @param ClientId $clientId
     */
    public function delete(ClientId $clientId);
}
