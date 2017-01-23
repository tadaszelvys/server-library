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

namespace OAuth2\Event\AccessToken;

use OAuth2\Model\AccessToken\AccessTokenId;
use OAuth2\Model\Event\Event;

final class AccessTokenRevokedEvent extends Event
{
    /**
     * @var AccessTokenId
     */
    private $accessTokenId;

    /**
     * AccessTokenRevokedEvent constructor.
     *
     * @param $accessTokenId
     */
    protected function __construct(AccessTokenId $accessTokenId)
    {
        parent::__construct();
        $this->accessTokenId = $accessTokenId;
    }

    /**
     * @param AccessTokenId $accessTokenId
     *
     * @return self
     */
    public static function create(AccessTokenId $accessTokenId): self
    {
        return new self($accessTokenId);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): \JsonSerializable
    {
        return $this->accessTokenId;
    }
}
