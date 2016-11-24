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
use OAuth2\Model\Client\Client;
use OAuth2\Model\Client\ClientId;
use OAuth2\Model\Client\ClientRepositoryInterface;
use OAuth2\Model\UserAccount\UserAccount;
use Ramsey\Uuid\Uuid;

class ClientRepository implements ClientRepositoryInterface
{
    /**
     * @var Client[]
     */
    private $clients = [];

    /**
     * {@inheritdoc}
     */
    public function create(UserAccount $userAccount, array $metadatas)
    {
        $clientId = ClientId::create(Uuid::uuid4()->toString());

        return Client::create($clientId, $metadatas, $userAccount);
    }

    /**
     * {@inheritdoc}
     */
    public function find(ClientId $clientId)
    {
        return array_key_exists($clientId->getValue(), $this->clients) ? $this->clients[$clientId->getValue()] : null;
    }

    /**
     * {@inheritdoc}
     */
    public function findAll()
    {
        return array_values($this->clients);
    }

    /**
     * {@inheritdoc}
     */
    public function save(Client $client)
    {
        $this->clients[$client->getId()->getValue()] = $client;
    }

    /**
     * {@inheritdoc}
     */
    public function delete(Client $client)
    {
        $client = $this->find($client->getId());
        Assertion::notNull($client, 'Unknown client.');
        unset($this->clients[$client->get('client_id')]);
    }
}
