<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\OpenIdConnect\NoneResponseTypeListenerInterface;

class NoneListener implements NoneResponseTypeListenerInterface
{
    /**
     * @var AccessToken[]
     */
    private $accessTokens = [];

    /**
     * [@inheritdoc}.
     */
    public function call(AccessToken $accessToken)
    {
        $this->accessTokens[] = $accessToken;
    }

    /**
     * @return AccessToken[]
     */
    public function getAccessTokens()
    {
        return $this->accessTokens;
    }
}
