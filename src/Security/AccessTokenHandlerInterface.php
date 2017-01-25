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

namespace OAuth2\Security;

use OAuth2\Model\AccessToken\AccessToken;

interface AccessTokenHandlerInterface
{
    /**
     * @param string $token
     *
     * @return null|AccessToken
     */
    public function find(string $token);
}
