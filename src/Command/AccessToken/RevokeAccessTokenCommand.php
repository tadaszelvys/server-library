<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\AccessToken;

use OAuth2\Model\AccessToken\AccessToken;

final class RevokeAccessTokenCommand
{
    /**
     * @var AccessToken
     */
    private $accessToken;

    /**
     * RevokeAccessTokenCommand constructor.
     *
     * @param AccessToken $accessToken
     */
    protected function __construct(AccessToken $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @param AccessToken $accessToken
     *
     * @return RevokeAccessTokenCommand
     */
    public static function create(AccessToken $accessToken): self
    {
        return new self($accessToken);
    }

    /**
     * @return AccessToken
     */
    public function getAccessToken(): AccessToken
    {
        return $this->accessToken;
    }
}
