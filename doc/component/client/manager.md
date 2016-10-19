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

#### Sector Identifier Uri Rule

The class `OAuth2\Client\Rule\SectorIdentifierUriRule` will allow you to define sector identifier Uris for your client.
This rule should be used only if the server support OpenID Connect functionality.

Supported parameters is:

- `sector_identifier_uri`

#### Software Rule

The class `OAuth2\Client\Rule\SoftwareRule` will allow you to support the Software Statement.
This rule should be used only if you enabled the Software Statement functionality on the Client Registration Endpoint.

Supported parameters is:

- `software_statement`

#### Subject Type Rule

The class `OAuth2\Client\Rule\SubjectTypeRule` will allow you to choose the subject type used by your client.
This rule should be used only if you enabled the OpenID Connect and custom subject type (e.g. pairwise) are enabled.

Supported parameters is:

- `subject_type`

#### Client Registration Management Rule

The abstract class `OAuth2\Client\Rule\ClientRegistrationManagementRule` will allow your clients to be managed using a dedicated Uri.
As this management Uri is not yet available, this rule is not described here.

#### Custom Rule

You can define any type of rule by implementing the interface `OAuth2\Client\Rule\RuleInterface`.
If the parameter you want to check can be internationalized, then we recommend you to extend the class `OAuth2\Client\Rule\AbstractInternationalizedRule`.

Hereafter an example with a `description` parameter.
With this simple class you will be able to set an internationalized description parameter (`description`, `description#en`, `description#fr_FR`...) for each of your clients.

Note that we use a closure (optional) to check the key and the value of the parameter.
In this example, we check check the parameter is a string.

```php
<?php

namespace App\Rule;

use Assert\Assertion;
use OAuth2\Client\ClientInterface;
use OAuth2\Client\Rule\AbstractInternationalizedRule;

final class DescriptionRule extends AbstractInternationalizedRule
{
    /**
     * {@inheritdoc}
     */
    public function check(ClientInterface $client, array $registration_parameters)
    {
        $parameters = $this->getInternationalizedParameters(
            $registration_parameters, // The parameters
            'description',            // The internationalized parameter the rule is looking for
            function($k, $v) {Assertion::url($v, sprintf('The parameter with key "%s" is not a valid URL.', $k));}
        );
        
        foreach ($parameters as $k => $v) {
            $client->set($k, $v);
        }
    }
}
```
