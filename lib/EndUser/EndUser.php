<?php

namespace OAuth2\EndUser;

use OAuth2\ResourceOwner\ResourceOwner;

/**
 * This interface must be implemented by end-user classes.
 */
class EndUser extends ResourceOwner implements EndUserInterface
{
    private $last_login_at = null;

    public function __construct()
    {
        parent::__construct();
        $this->setType('end_user');
    }

    public function getLastLoginAt()
    {
        return $this->last_login_at;
    }
}
