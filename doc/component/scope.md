Scope Manager And Scopes
========================

This library allows access tokens to support scopes.
These scopes are handled by a dedicated component: the Scope Manager.

# Basic Usage

This library provides a simple scope manager class `OAuth2\Scope\ScopeManager`:
It is able to manage multiple scopes and verify client requests.

Let say you want to support the following scopes: `read`, `read_write`, `delete`.


```php
use OAuth2\Scope\ScopeManager;

$scope_manager = new ScopeManager(
    $exception_manager,
    ['read', 'read_write', 'delete']
);
```

*Please note that the variable `$exception_manager` is an instance of your exception manager. See [this page](exception.md) for more information.*

You can now inject `$scope_manager` to other components that require the scope manager.

# Scope Policies

The [RFC6749, section 3.3,](https://tools.ietf.org/html/rfc6749#section-3.3) introduces scope policies `default` and `error` applied on client requests.

This library support these policies.

## No Scope Policy

If the policy is not defined, nothing will append. This is the default behaviour.

```php
use OAuth2\Scope\ScopeManager;
use OAuth2\Scope\ScopeManagerInterface;

$scope_manager = new ScopeManager(
    $exception_manager,
    ['read', 'read_write', 'delete'],         // Available scopes
    [],
    ScopeManagerInterface::POLICY_MODE_NONE  // Scope policy
);
```

## Scope Policy 'Default'

When no scope is set in the client request, the default scopes are set.

```php
use OAuth2\Scope\ScopeManager;
use OAuth2\Scope\ScopeManagerInterface;

$scope_manager = new ScopeManager(
    $exception_manager,
    ['read', 'read_write', 'delete'],           // Available scopes
    ['read'],                                   // Default scopes
    ScopeManagerInterface::POLICY_MODE_DEFAULT  // Scope policy
);
```

Example #1:

> A client sends a request without scope parameter. If an access token is issued, the scope `read` is associated to the access token.

Example #2:

> A client sends a request with scope parameter `read_write delete`. If an access token is issued, the scope `read_write delete` are associated to the access token.

## Scope Policy 'Error'

When no scope is set in the client request, an error is thrown.

```php
use OAuth2\Scope\ScopeManager;
use OAuth2\Scope\ScopeManagerInterface;

$scope_manager = new ScopeManager(
    $exception_manager,
    ['read', 'read_write', 'delete'],         // Available scopes
    [], 
    ScopeManagerInterface::POLICY_MODE_ERROR  // Scope policy
);
```

Example #1:

> A client sends a request without scope parameter. An error is thrown and no access token is issued.

Example #2:

> A client sends a request with scope parameter `read_write delete`. If an access token is issued, the scope `read_write delete` are associated to the access token.

# Scope and Scope Policy Per Client

The scope manager is able to support scope and scope policy per client.

To enable this feature, your client class must implement the interface `OAuth2\Client\ScopeExtensionInterface`.

In the following example, clients based on the class `Acme\PublicClient` have scope policy set to `POLICY_MODE_DEFAULT` and scope `read` is set by default if no scope is requested.
Available scopes are not changed.

```php
<?php
namespace Acme;

use OAuth2\Client\PublicClient as Base;
use OAuth2\Client\ScopeExtensionInterface;
use OAuth2\Scope\ScopeManagerInterface;

class PublicClient extends Base implements ScopeExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getAvailableScopes(ServerRequestInterface $request = null)
    {
        //We return nothing, it means that the available scopes are the same as those set in the scope manager.
        //The same goes for other methods: if nothing is returned then the scope manager parameter is used.
    }
    
    /**
     * {@inheritdoc}
     */
    public function getDefaultScopes(ServerRequestInterface $request = null)
    {
        return [
            'read',
        ];
    }
    
    /**
     * {@inheritdoc}
     */
    public function getScopePolicy(ServerRequestInterface $request = null)
    {
        return ScopeManagerInterface::POLICY_MODE_DEFAULT;
    }
}
```

# My OAuth2 Server Does Not Need Scope

Even if you do not want to add this feature, you must create a scope manager.
You just have to create an instance of the `ScopeManager` class and inject it.

```php
use OAuth2\Scope\ScopeManager;

$scope_manager = new ScopeManager(
    $exception_manager
);
```
