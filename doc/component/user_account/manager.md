# Users And Accounts

This library needs user accounts but no users. Why?
There are several reasons:

* This library can be integrated into any kind of projects as your user management is not impacted,
* A user can have multiple identities/accounts,
* It allows a user to manage all its resources whatever the chosen account during the consent process.

All you have to do is to create an User Account and an User Account Manager class.

## User Account Class

This architecture means there is not relationship between a user and user accounts.
Each user must have a unique public ID and each user account is linked to a user public ID.

An user account must implement the interface `OAuth2\UserAccount\UserAccountInterface`.
This interface extends the interface `OAuth2\ResourceOwner\ResourceOwnerInterface`.

An abstract user account class is also available: `OAuth2\UserAccount\UserAccount`.
You have to implement the missing methods or create your own class.

```php
<?php

namespace App;

use OAuth2\UserAccount\UserAccount as Base;

class UserAccount extends Base
{
    /**
     * @return string
     */
    private $user_public_id;
    
    /**
     * @return null|int
     */
    private $last_login_at = null;
    
    /**
     * @param string $user_public_id
     */
    public function __construct($user_public_id)
    {
        parent::__construct();
        $this->user_public_id = $user_public_id;
    }

    /**
     * This method returns the timestamp of the last login of the user.
     * In general, you will return either the login timestamp of the user with this user account
     * or the login timestamp of the user itself.
     * 
     * {@inheritdoc}
     */
    public function getLastLoginAt()
    {
        return $this->last_login_at;
    }

    /**
     * Each user account is linked to a user public ID.
     * 
     * {@inheritdoc}
     */
    public function getUserPublicId()
    {
        return $this->user_public_id;
    }
}
```

## User Account Manager

Now that you defined your user accounts, you have to create an user accounts manager.
Tha manager has to implement the interface `OAuth2\UserAccountUserAccountManagerInterface` and its methods.

Hereafter a simple example (explanations in comments).

```php
<?php

namespace App;

use OAuth2\UserAccount\UserAccountInterface;
use OAuth2\UserAccount\UserAccountManagerInterface;

class UserAccountManager implements UserAccountManagerInterface
{
    /**
     * This manager will store all users in this array.
     * In your case, a DB connection or an external service (e.g. SCIM server) should be better
     * The way you manage the user accounts is not described here.
     * It is up to you to implement all needed methods to create and save them.
     * 
     * @var \OAuth2\UserAccount\UserAccountInterface[]
     */
    private $user_accounts = [];

    /**
     * This method will verify the password of the user account is valid.
     * We verify the account has a password. If not then we return false; this means the request will be rejected.
     * Else, we compare the password of the account with the argument.
     * In production, the account password may be hashed or encrypted.
     * 
     * {@inheritdoc}
     */
    public function checkUserAccountPasswordCredentials(UserAccountInterface $resource_owner, $password)
    {
        if (!$resource_owner->has('password')) {
            return false;
        }
        
        // Idea #1: You may also verify the password has not expired.
        // Idea #2: To verify which client requests a password validation, you can associate a password to a client and log successful login attempts.
        //          This kind of feature is similar to the App password provided by Google (see https://support.google.com/mail/answer/185833?hl=en)
        
        return hash_equals($password, $resource_owner->get('password'));
    }

    /**
     * This method is used to find a user account using a username.
     * In this example, we do not manage user names, but public IDs.
     * In general, this method should execute a DB query to find it out.
     * 
     * Return an object that implements UserAccountInterface or null (not found)
     * 
     * {@inheritdoc}
     */
    public function getUserAccountByUsername($username)
    {
        return $this->getUserAccountByPublicId($username);
    }

    /**
     * This method is used to find a user account using a public ID.
     * In this example, we just check the $user_account array has the specified public ID as a key.
     * In general, this method should execute a DB query to find it out.
     * 
     * Return an object that implements UserAccountInterface or null (not found)
     * 
     * {@inheritdoc}
     */
    public function getUserAccountByPublicId($public_id)
    {
        return array_key_exists($public_id, $this->user_accounts) ? $this->user_accounts[$public_id] : null;
    }

    /**
     * This method is used by the discovery service provided by the OpenID Connect feature.
     * It allows you to find a user account using its resource name.
     * A resource name could be something like:
     * - "https://my-service.com:9000/~john.doe"
     * - "acct:john.doe@my-service.com:9000"
     * 
     * If you do not need the discovery service, then just return null.
     * 
     * {@inheritdoc}
     */
    public function getUserAccountFromResource($resource)
    {
        $server = 'my-service.com:9000';
        $length = mb_strlen($server, 'utf-8');
        if ('https://'.$server.'/+' === mb_substr($resource, 0, $length + 10, 'utf-8')) {
            $public_id = mb_substr($resource, $length + 10, null, 'utf-8');
        } elseif ('acct:' === mb_substr($resource, 0, 5, 'utf-8') && '@'.$server === mb_substr($resource, -($length + 1), null, 'utf-8')) {
            $public_id = mb_substr($resource, 5, -($length + 1), 'utf-8');
        } else {
            return null;
        }

        return array_key_exists($public_id, $this->user_accounts) ? $this->user_accounts[$resource] : null;
    }
}
```
