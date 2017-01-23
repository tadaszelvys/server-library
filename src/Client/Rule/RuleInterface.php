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

use OAuth2\Model\UserAccount\UserAccountId;

interface RuleInterface
{
    /**
     * @param array         $command_parameters
     * @param array         $validated_parameters
     * @param UserAccountId $userAccountId
     * @param callable      $next
     *
     * @return array
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccountId $userAccountId, callable $next);
}
