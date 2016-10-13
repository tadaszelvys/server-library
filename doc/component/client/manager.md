# Client Manager

Clients (or third party applications) are a very important part of the OAuth2 Framework Protocol.
With this library, all clients are managed by a client manager.

## Client Class

The client class must implement `OAuth2\Client\ClientInterface`.
A client class is available: `OAuth2\Client\Client`.

## Client Manager Class

That manager must implement `OAuth2\Client\ClientManagerInterface`.
An abstract client manager is available: `OAuth2\Client\ClientManager`.

```php
<?php

namespace App;

use OAuth2\Client\ClientInterface;
use OAuth2\Client\ClientManager as Base;

class ClientManager extends Base
{
    /**
     * @var \OAuth2\Client\ClientInterface[]
     */
    private $clients = [];

    /**
     * This method is used to retrieve the client with th client ID passed in argument.
     * It must return null if not found.
     * This example stores clients in a variable, but you should use a DB connection or an external service.
     * 
     * {@inheritdoc}
     */
    public function getClient($client_id)
    {
        return isset($this->clients[$client_id]) ? $this->clients[$client_id] : null;
    }

    /**
     * This method will save the client passed in argument.
     * 
     * {@inheritdoc}
     */
    public function saveClient(ClientInterface $client)
    {
        $this->clients[$client->getPublicId()] = $client;
    }
}
```

## Client Creation

At the moment, the only way to safely create a client is to use the Client Registration Endpoint.
