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

interface ScopeInterface
{
    /**
     * @return string The name of the scope
     */
    public function getName();
}
