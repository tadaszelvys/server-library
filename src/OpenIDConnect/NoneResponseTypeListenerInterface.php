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

use OAuth2\Token\AccessTokenInterface;

interface NoneResponseTypeListenerInterface
{
    public function call(AccessTokenInterface $access_token);
}
