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

namespace OAuth2\Client\Rule;

use OAuth2\Model\UserAccount\UserAccount;

interface RuleManagerInterface
{
    /**
     * @param array       $parameters
     * @param UserAccount $userAccount
     *
     * @return array
     */
    public function handle(array $parameters, UserAccount $userAccount);
}
