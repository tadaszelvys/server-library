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

According to the [RFC6749, section 3.3,](https://tools.ietf.org/html/rfc6749#section-3.3) ,if the client omits the scope parameter when requesting authorization, the authorization server must either process the request using a pre-defined default value or fail the request indicating an invalid scope.

To comply with the specifitation, the scope managr is able to support scope policies.

## No Scope Policy

If the policy is not defined (default), the scope parameter (if passed as an argument) is not changed. This is the default behaviour.

> A client sends a request without scope parameter. If an access token is issued, no scope is associated to the access token.

## Scope Policy 'Default'

When no scope is set in the client request, the default scopes are set.

```php
use OAuth2\Scope\DefaultScopePolicy;

// We create an instance of our scope policy
$default_scope_policy = new DefaultScopePolicy(['read']);

// We add it and we specify it is the default policy
$scope_manager->addScopePolicy($default_scope_policy, true);
```

> A client sends a request without scope parameter. If an access token is issued, the scope `read` is associated to the access token.

## Scope Policy 'Error'

When no scope is set in the client request, an error is thrown.

```php
use OAuth2\Scope\ErrorScopePolicy;

// We create an instance of our scope policy
$error_scope_policy = new ErrorScopePolicy($exception_manager);

// We add it and we specify it is the default policy
$scope_manager->addScopePolicy($error_scope_policy, true);
```

> A client sends a request without scope parameter. An error is thrown and no access token is issued.

## Custom Scope Policy

If you want to set your own policy, just create a class that implements `OAuth2\Scope\ScopePolicyInterface`.

# Scope and Scope Policy Per Client

The scope manager is able to support scope and scope policy per client.

To enable this feature, your client class must implement the interface `OAuth2\Client\ScopeExtensionInterface`.

In the following example, clients based on the class `Acme\PublicClient` have scope policy set to `default` and scope `read` is set by default if no scope is requested.
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
    public function getAvailableScopes()
    {
        // We return nothing (or null), it means that the available scopes are the same as those set in the scope manager.
        // The same goes for other methods: if nothing is returned then the scope manager parameter is used.
        // If you want to limit or add scope for this client, you must return a list of the scopes
        // e.g.: ['read', 'delete', 'undelete'] means the scope 'read_write' is unavailable but the scope 'undelete' is added
        // You should avoid to add new scope using this method, but you are free to limit them
        // e.g. confidential client have full access on the scopes, but public client only have the 'read' and 'read_write' scopes
    }
    
    /**
     * {@inheritdoc}
     */
    public function getScopePolicy()
    {
        // If you return nothin, it means that the scope policy is unchanged. The default policy will be used.
        // Else, the specified policy will be applied.
        return 'default';
    }
}
```

# My OAuth2 Server Does Not Need Scope

Even if you do not want to add this feature, you must create a scope manager.
You just have to create an instance of the `ScopeManager` class and inject it.

```php
use OAuth2\Scope\ScopeManager;

$scope_manager = new ScopeManager($exception_manager);
```
>>>>>>> origin/master
