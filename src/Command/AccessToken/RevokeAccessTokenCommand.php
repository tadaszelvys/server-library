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

namespace OAuth2\Command\AccessToken;

use OAuth2\Model\AccessToken\AccessTokenId;

final class RevokeAccessTokenCommand
{
    /**
     * @var AccessTokenId
     */
    private $accessTokenId;

    /**
     * RevokeAccessTokenIdCommand constructor.
     *
     * @param AccessTokenId $accessTokenId
     */
    protected function __construct(AccessTokenId $accessTokenId)
    {
        $this->accessTokenId = $accessTokenId;
    }

    /**
     * @param AccessTokenId $accessTokenId
     *
     * @return RevokeAccessTokenCommand
     */
    public static function create(AccessTokenId $accessTokenId): self
    {
        return new self($accessTokenId);
    }

    /**
     * @return AccessTokenId
     */
    public function getAccessTokenId(): AccessTokenId
    {
        return $this->accessTokenId;
    }
}
