Users And Accounts
==================

This library needs users and user accounts. Why?
There are several benefits:

* This library can be integrated into any kind of projects as your user management is not impacted,
* A user can have multiple identities/accounts,
* It allows a user to manage all its resources whatever the chosen account during the consent process.

The users class just have to implement the interface `OAuth2\User\UserInterface`.
There are only two methods to implement:

* `public function getAccounts();`: a list of user accounts,
* `public function getPublicId();`: the public ID of the user.

Each user must have at least one user account.
A user account must implement the interface `OAuth2\UserAccount\UserAccountInterface`.