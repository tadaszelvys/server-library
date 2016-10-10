Exceptions and Exception Manager
================================

The exception manager manages all exception types thrown during the authorization process.
It is used by almost all other components.

You can create it just by instantiating the class `OAuth2\Exception\ExceptionManager`.

```php
use OAuth2\Exception\ExceptionManager;

$exception_manager = new ExceptionManager();
```

Now the variable `$exception_manager` can be injected to all other components that require an exception manager.

# Advanced

## Extensions

The exception manager allow you to add error data using extensions.
For example, your authorization server may provide pages containing human readable error descriptions.
You can add the `error_uri` parameter for all returned error or a certain type of them.

To do so, you just have to create and add an extension using the menthod `addExtension`.
This extension must implement `OAuth2\Exception\Extension\ExceptionExtensionInterface`.

The following example shows you how to define an error URI for bad request errors only:

First, we create our extension:

```php
namespace Acme;

use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\Exception\Extension\ExceptionExtensionInterface;

/**
 */
class UriExtension implements ExceptionExtensionInterface
{
    /**
     * {@inheritdoc}
     */
    public function process($type, $error, $error_description, array &$data)
    {
        if ($type !== ExceptionManagerInterface::INTERNAL_SERVER_ERROR) {
            $data['error_uri'] = "https://foo.test/Error/$type/$error";
        } else {
            $data['error_uri'] = "https://foo.test/Internal/$type/$error";
        }
    }
}
```

Then, we add this extension to the exception manager:

```php
$exception_manager->addExtension(new UriExtension());
```

## Custom Exception Type

When you create a new endpoint, grant type or any other component, you may need to return a custom exception.
The exception manager is able to support new exception types.

Let say you want to limit requests from some clients. You could need to create an error that returns a HTTP 429 error (Too Many Requests)

```php
namespace Acme;

use OAuth2\Exception\BaseException;

class TooManyRequestsException extends BaseException
{
    /**
     * {@inheritdoc}
     */
    public function __construct($error, $error_description, array $error_data)
    {
        parent::__construct(429, $error, $error_description, $error_data);
    }
}
```

Then, you have to create an exception factory. This factory will create exceptions with that new type.

```php
namespace Acme;

use OAuth2\Exception\Factory\ExceptionFactoryInterface;

class TooManyRequestsExceptionFactory implements ExceptionFactoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getType()
    {
        return 'TooManyRequests';
    }

    /**
     * {@inheritdoc}
     */
    public function createException($error, $error_description, array $error_data, array $data)
    {
        // We just return the exception with parameters, but you can add all your application logic here.
        return new TooManyRequestsException($error, $error_description, $error_data, $data);
    }
}
```

Then, you just have to add this class to the class mapping of the exception manager:

```php
use  Acme\TooManyRequestsExceptionFactory;
$exception_manager->addExceptionFactory(new TooManyRequestsExceptionFactory());
```

Now, you are able to throw your new exception type:

```php
throw $exception_manager->getException('TooManyRequests', 'unauthorized_client', 'Only 300 requests/day');
// Or
throw $exception_manager->getTooManyRequestsException('unauthorized_client', 'Only 300 requests/day');
```
