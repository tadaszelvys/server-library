<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Scope;

use OAuth2\Client\ClientInterface;
use Psr\Http\Message\ServerRequestInterface;

class ErrorScopePolicy implements ScopePolicyInterface
{
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'error';
    }

    /**
     * {@inheritdoc}
     */
    public function checkScopePolicy(array &$scope, ClientInterface $client, ServerRequestInterface $request = null)
    {
        throw new \InvalidArgumentException('No scope was requested.');
    }
}
