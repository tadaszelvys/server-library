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

final class AccessTokenHandlerManager
{
    /**
     * @var AccessTokenHandlerInterface[]
     */
    private $accessTokenHandlers = [];

    /**
     * @param AccessTokenHandlerInterface $accessTokenHandler
     *
     * @return AccessTokenHandlerManager
     */
    public function add(AccessTokenHandlerInterface $accessTokenHandler): AccessTokenHandlerManager
    {
        $this->accessTokenHandlers[] = $accessTokenHandler;

        return $this;
    }

    /**
     * @param string $token
     *
     * @return null|AccessToken
     */
    public function find(string $token)
    {
        foreach ($this->accessTokenHandlers as $accessTokenHandler) {
            $accessToken = $accessTokenHandler->find($token);
            if (null !== $accessToken) {
                return $accessToken;
            }
        }
    }
}
