<?php

namespace OAuth2\EndUser;

use OAuth2\ResourceOwner\ResourceOwnerInterface;

/**
 * This interface must be implemented by end-user classes.
 */
interface EndUserInterface extends ResourceOwnerInterface
{
    /**
     * @return null|int
     */
    public function getLastLoginAt();

    /**
     * @param null|int $last_login_at
     *
     * @return self
     */
    public function setLastLoginAt($last_login_at);
}
