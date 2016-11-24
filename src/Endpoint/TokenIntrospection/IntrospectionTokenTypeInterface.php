<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\TokenIntrospection;

use OAuth2\Model\Client\Client;

interface IntrospectionTokenTypeInterface
{
    /**
     * @return string
     */
    public function getTokenTypeHint(): string;

    /**
     * @param string $token
     * @param Client $client
     *
     * @return array
     */
    public function introspectToken(string $token, Client $client);
}
