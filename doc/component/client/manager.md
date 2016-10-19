# Client Manager

Clients (or third party applications) are a very important part of the OAuth2 Framework Protocol.
With this library, all clients are managed by a client manager.

## Client Class

The client class must implement `OAuth2\Client\ClientInterface`.
A client class is available: `OAuth2\Client\Client`.

## Client Manager Class

That manager must implement `OAuth2\Client\ClientManagerInterface`.

An abstract client manager is available: `OAuth2\Client\ClientManager`.
The methods you have to implement are just those needed to get a client from its public ID or to save into your storage (e.g. database).

In the following, we just store them in the memory:

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

$client_manager = new ClientManager();
$client_manager->createClient();
```

Now you can create an instance of your Client Manager and use it:

```php
<?php

$client_manager = new ClientManager();
```

## Client Creation

To create a client, you can call the method `createClient()` of the Client Manager.
This method just create an empty client. By default only the `client_id` and the `client_id_issued_at` parameters are set.

You can populate the client with your own parameters before you save it.
This is not the recommended method unless you know exactly what your are doing with clients.
The preferred way is to add rules and use the method `createClientFromParameters`.

### Rules

Rules will verify all supported parameters and throw exception when something when wrong.
This library provides some rules out of the box. Just create an instance and add it to the client manager using the method `addRule`.

*Note: parameters that are marked "multi-languages supported" means you can add a suffix with the language and region of the parameter.*
*For example `client_name`, `client_name#fr_Fr`, `client_name#en` or `client_name#de_AU` are valid parameters.*

#### Common Parameters Rule

The class `OAuth2\Client\Rule\CommonParametersRule` will verify the following parameters are valid:

- `client_name`: The name of the client (optional, recommended, multi-languages supported)
- `client_uri`: The Uri to get information about the client (optional)
- `logo_uri`: The Uri to get the logo of the client (optional)
- `tos_uri`: The Uri for Terms of Service of the client (optional)
- `policy_uri`: The Uri for Policy of the client (optional)

#### Grant Type Rule

The class `OAuth2\Client\Rule\GrantTypeFlowRule` will verify the selected grant types.
It requires the grant type and the response type managers.

Supported parameters are:

- `grant_types`
- `response_types`

#### Redirect Uri Rule

The class `OAuth2\Client\Rule\RedirectionUriRule` will verify the registered redirect Uris.

Supported parameters is:

- `redirect_uris`

#### Scope Rule

The class `OAuth2\Client\Rule\ScopeRule` will verify the selected scopes.
This rule is useful only if you use scope.

Supported parameters are:

- `scope`
- `scope_policy`
- `default_scope`

#### Id Token Encryption Algorithms Rule

The class `OAuth2\Client\Rule\IdTokenEncryptionAlgorithmsRule` will verify the selected Id Token encryption algorithms.
This rule should be used only if the Id Token is supported and the server/client have encryption capabilities.

Supported parameters are:

- `id_token_encrypted_response_alg`
- `id_token_encrypted_response_enc`

#### Request Uri Rule

The class `OAuth2\Client\Rule\RequestUriRule` will verify the selected request Uris.
This rule should be used only if the server support Referenced Request Objects.

Supported parameters is:

- `request_uris`
