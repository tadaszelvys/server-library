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

namespace OAuth2\ResponseType;

use OAuth2\Model\AccessToken\AccessToken;

/**
 * Should be remplaced by a Command/Event.
 */
interface NoneResponseTypeListenerInterface
{
    /**
     * @param AccessToken $access_token
     */
    public function call(AccessToken $access_token);
}
