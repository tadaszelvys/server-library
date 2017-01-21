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

use OAuth2\Model\AccessToken\AccessToken;
use OAuth2\Model\Event\Event;

final class AccessTokenCreatedEvent extends Event
{
    /**
     * @var AccessToken
     */
    private $accessToken;

    /**
     * AccessTokenCreatedEvent constructor.
     *
     * @param $accessToken
     */
    protected function __construct(AccessToken $accessToken)
    {
        parent::__construct();
        $this->accessToken = $accessToken;
    }

    /**
     * @param AccessToken $accessToken
     *
     * @return self
     */
    public static function create(AccessToken $accessToken): self
    {
        return new self($accessToken);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): \JsonSerializable
    {
        return $this->accessToken;
    }
}
