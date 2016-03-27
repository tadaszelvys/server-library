Client Manager Supervisor
=========================

The role of the client manager supervisor is to manage all client managers you need.
It will handle requests and try to identify which client is sending requests against the authorization server.

```php
use OAuth2\Client\ClientManagerSupervisor;

$client_manager_supervisor = new ClientManagerSupervisor($exception_manager);
```

Now you can add your client managers using the method `addClientManager`:

```php
$client_manager_supervisor->addClientManager($my_client_manager);
```

This library provides classes to handle the following client manager:

* Public Clients
* Password Clients
* JWT Clients
* Unregistered Clients
