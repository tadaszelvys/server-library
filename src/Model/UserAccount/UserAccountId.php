<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\UserAccount;

use OAuth2\Model\ResourceOwner\ResourceOwnerId;

final class UserAccountId extends ResourceOwnerId
{
    /**
     * @param string $value
     * @return UserAccountId
     */
    public static function create(string $value): self
    {
        return new self($value);
    }
}
