<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Client\ClientInterface;
use OAuth2\OpenIDConnect\IdTokenClaimManagerInterface;
use OAuth2\User\UserInterface as BaseUserInterface;

final class FooClaim implements IdTokenClaimManagerInterface
{
    public function process(array &$claims, array &$header, BaseUserInterface $user, ClientInterface $client)
    {
        $claims['foo'] = 'bar';
        if (!array_key_exists('crit', $header)) {
            $header['crit'] = [];
        }
        if (!is_array($header['crit'])) {
            $header['crit'] = [$header['crit']];
        }

        $header['crit'] = array_merge($header['crit'], ['foo']);
    }
}
