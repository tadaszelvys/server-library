Scope Manager And Scopes
========================

This library allows access tokens to support scopes.
These scopes are handled by a dedicated component: the Scope Manager.

The scope manager must implement `OAuth2\Scope\ScopeManagerInterface`.
This library provides a simple scope manager class `OAuth2\Scope\ScopeManager`:
It is able to manage multiple scopes and verify client requests.
If this scope manager does not fit on your needs, you can create your own or extend it.

# Basic Usage

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

According to the [RFC6749, section 3.3,](https://tools.ietf.org/html/rfc6749#section-3.3), if the client omits the scope parameter when requesting authorization, the authorization server must either process the request using a pre-defined default value or fail the request indicating an invalid scope.

To comply with the specification, the scope manager is able to support scope policies.

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

# Per Client Rules

## Scope Policy Per Client

The scope manager is able to support scope policy per client.

To enable this feature, your client class must implement the interface `OAuth2\Client\Extension\ScopePolicyExtensionInterface`.

In the following example, clients based on the class `Acme\PublicClient` have scope policy set to `default`.

```php
<?php
namespace Acme;

use OAuth2\Client\PublicClient as Base;
use OAuth2\Client\Extension\ScopePolicyExtensionInterface;

class PublicClient extends Base implements ScopePolicyExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getScopePolicy()
    {
        // If you return nothing, it means that the scope policy is unchanged. The default policy will be used.
        // Else, the specified policy will be applied.
        return 'default';
    }
}
```

## Available Scopes Per Client

The scope manager is able to modify scope available per client.

To enable this feature, your client class must implement the interface `OAuth2\Client\Extension\AvailableScopeExtensionInterface`.

In the following example, clients based on the class `Acme\PublicClient` have only scope `['read', 'read_write']`. The scope `delete` is not available.

```php
<?php
namespace Acme;

use OAuth2\Client\PublicClient as Base;
use OAuth2\Client\Extension\AvailableScopeExtensionInterface;

class PublicClient extends Base implements AvailableScopeExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getAvailableScopes()
    {
        return ['read', 'read_write'];
    }
    
}
```

Please note that you can add new scope using this extension. For example, if you return `['delete', 'undelete']`, the scope `undelete` is created.
We do not recommend to create new scopes using this extension, but limit the available scopes. 

## Default Scopes Per Client

The scope manager is able to support default scope per client. This feature is only useful if the scope policy applied for the client is `default`.

To enable this feature, your client class must implement the interface `OAuth2\Client\Extension\DefaultScopeExtensionInterface`.

In the following example, clients based on the class `Acme\PublicClient` have default scope set to `['read']`.

```php
<?php
namespace Acme;

use OAuth2\Client\PublicClient as Base;
use OAuth2\Client\Extension\DefaultScopeExtensionInterface;

class PublicClient extends Base implements DefaultScopeExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getDefaultScope()
    {
        return ['read'];
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
