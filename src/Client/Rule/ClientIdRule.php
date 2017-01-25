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
use Ramsey\Uuid\Uuid;

final class ClientIdRule implements RuleInterface
{
    /**
     * {@inheritdoc}
     */
    public function handle(array $commandParameters, array $validatedParameters, UserAccountId $userAccountId, callable $next)
    {
        $validatedParameters['client_id'] = Uuid::uuid4()->toString();
        $validatedParameters['client_id_issued_at'] = time();

        return $next($commandParameters, $validatedParameters, $userAccountId);
    }
}
