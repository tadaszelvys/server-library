<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIDConnect;

use OAuth2\Client\ClientInterface;
use OAuth2\EndUser\EndUserInterface;

interface IdTokenClaimManagerInterface
{
    /**
     * @param array                            $claims
     * @param \OAuth2\EndUser\EndUserInterface $end_user
     * @param \OAuth2\Client\ClientInterface   $client
     *
     * @return mixed
     */
    public function process(array &$claims, EndUserInterface $end_user, ClientInterface $client);
}
