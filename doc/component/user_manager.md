Users and User Manager
======================

The user management is out of the scope of the OAuth2 Framework Protocol, but this library needs methods to get a user from its username
and to verify if the credentials used by the client (in case of the `password` grant type is used) are valid.

# Users

All user must implement the interface `OAuth2\User\UserInterface`.
This interface is just an extension of the `OAuth2\ResourceOwner\ResourceOwnerInterface` and does not require new methods to be implemented.
We also provide traits to ease the integration of the user in your application.

Example:

```php
<?php

namespace Acme;

use Base64Url\Base64Url;
use OAuth2\ResourceOwner\ResourceOwnerTrait;
use OAuth2\User\UserInterface;
use OAuth2\User\UserTrait;

class User implements UserInterface
{
    use ResourceOwnerTrait;
    use UserTrait;

    /**
     * @var string
     */
    private $username;

    /**
     * @var string
     */
    private $password;

    /**
     * User constructor.
     *
     * @param string $username
     * @param string $password
     */
    public function __construct($username, $password)
    {
        $this->setPublicId(trim(chunk_split(Base64Url::encode(uniqid(mt_rand(), true)), 16, '-'), '-'));
        $this->username = $username;
        $this->password = $password;
    }

    /**
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @return string
     */
    public function getPassword()
    {
        return $this->password;
    }
}
```

# User Manager

When your user class is defined, you have to provide a user manager.
This manager must implement the `OAuth2\User\UserManagerInterface` interface.

In the following example, we simply add users in an associative array and retrieve them using their unique public ID.
The method `checkUserPasswordCredentials` compare the secret with the input. The secret is not hashed or encrypted which is not recommended.

```php
<?php

namespace Acme;

use OAuth2\User\UserInterface;
use OAuth2\User\UserManagerInterface;

class UserManager implements UserManagerInterface
{
    /**
     * @var \OAuth2\User\UserInterface[]
     */
    private $users = [];
    
    /**
     * @param \OAuth2\User\UserInterface $user
     */
    public function addUser(UserInterface $user)
    {
        $this->users[$user->getPublicId()] = $user;
    }

    /**
     * {@inheritdoc}
     */
    public function checkUserPasswordCredentials(UserInterface $user, $password)
    {
        if (!$user instanceof User) {
            return false;
        }

        return hash_equals($password, $user->getPassword());
    }

    /**
     * {@inheritdoc}
     */
    public function getUser($public_id)
    {
        return array_key_exists($public_id, $this->users) ? $this->users[$public_id] : null;
    }
}
```

Now we can create an instance of this manager and inject it when necessary.
If you use a database, your method `getUser` will be a request against the database.
You must return `null` if no user has been found.

```php
use Acme\UserManager;

$user_manager = new UserManager();
```
