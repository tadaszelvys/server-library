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

## Error Redirect Uri

Your authorization server may provide pages containing error descriptions.
You can add an `error_uri` parameter for all returned error or a certain type of them.

To do so, you just have to extend the class `OAuth2\Exception\ExceptionManager` and override the method `getUri`.
If this method returns an URI, the `error_uri` parameter will be set.

The following example shows you how to define an error URI for bad request errors only:

```php
namespace Acme;

use OAuth2\Exception\ExceptionManager;

class MyExceptionManager extends ExceptionManager
{
    /**
     * {@inheritdoc}
     */
    public function getUri($type, $error, $error_description = null, array $data = [])
    {
        if (self::BAD_REQUEST === $type) {
            return sprintf(
                'https://my.service.example/oauth2/error/%s/%s',
                $error,
                null === $error_description?'':url_encode($error_description)
            );
        }
    }
}
```

## Custom Exception Type

When you create a new endpoint, grant type or any other component, you may need to return a custom exception.
The exception manager is able to support new exception types.

Let say you want to limit access token issuance for some clients. You could need to create an error that returns a HTTP 429 error (Too Many Requests)

```php
namespace Acme;

use OAuth2\Exception\BaseException;

class TooManyRequestsException extends BaseException
{
    /**
     * {@inheritdoc}
     */
    public function __construct($error, $error_description = null, $error_uri = null, array $data = [])
    {
        parent::__construct(429, $error, $error_description, $error_uri);
    }
}
```

> Please note that the constructor signature MUST be `public function __construct($code, $error, $error_description = null, $error_uri = null)`.

Then, you have to extend the class `OAuth2\Exception\ExceptionManager` and add your new exception type:

```php
namespace Acme;

use OAuth2\Exception\ExceptionManager;

class MyExceptionManager extends ExceptionManager
{
    /**
     * return array
     */
    protected function getExceptionTypeMap()
    {
        return array_merge(
            parent::getExceptionTypeMap(),
            [
                'TooManyRequests' => '\Acme\TooManyRequestsException',
            ]
        );
    }
}
```

Now, you are able to throw your new exception type:

```php
throw $exception_manager->getException('TooManyRequests', 'unauthorized_client', 'Only 300 requests/day');
// Or better
throw $exception_manager->getTooManyRequestsException('unauthorized_client', 'Only 300 requests/day');
```
