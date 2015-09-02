<?php

namespace OAuth2\EndUser;

use OAuth2\ResourceOwner\ResourceOwner;

/**
 * This interface must be implemented by end-user classes.
 */
class EndUser extends ResourceOwner implements EndUserInterface
{
    public function __construct()
    {
        $this->setType('end_user');
    }
}
