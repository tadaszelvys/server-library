<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Model\UserAccount;

use OAuth2\Model\ResourceOwner\ResourceOwner;

final class UserAccount extends ResourceOwner
{
    /**
     * UserAccount constructor.
     *
     * @param UserAccountId $id
     * @param array         $parameters
     */
    protected function __construct(UserAccountId $id, array $parameters)
    {
        parent::__construct($id, $parameters);
    }

    /**
     * @param UserAccountId $id
     * @param array         $parameters
     *
     * @return self
     */
    public static function create(UserAccountId $id, array $parameters): self
    {
        return new self($id, $parameters);
    }
}
