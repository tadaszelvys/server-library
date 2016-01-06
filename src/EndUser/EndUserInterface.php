<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

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
     */
    public function setLastLoginAt($last_login_at);
}
