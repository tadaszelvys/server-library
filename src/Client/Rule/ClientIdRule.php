<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Client\Rule;

use OAuth2\Model\UserAccount\UserAccount;
use Ramsey\Uuid\Uuid;

class ClientIdRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function handle(array $command_parameters, array $validated_parameters, UserAccount $userAccount, callable $next)
    {
        $validated_parameters['client_id'] = Uuid::uuid4()->toString();
        $validated_parameters['client_id_issued_at'] = time();

        return $next($command_parameters, $validated_parameters, $userAccount);
    }
}
