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

namespace OAuth2\Model\Scope;

use OAuth2\Model\Client\Client;
use Psr\Http\Message\ServerRequestInterface;

class ErrorScopePolicy implements ScopePolicyInterface
{
    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'error';
    }

    /**
     * {@inheritdoc}
     */
    public function checkScopePolicy(array &$scope, Client $client, ServerRequestInterface $request = null)
    {
        throw new \InvalidArgumentException('No scope was requested.');
    }
}
