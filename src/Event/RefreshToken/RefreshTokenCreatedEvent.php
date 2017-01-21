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

namespace OAuth2\Event\RefreshToken;

use OAuth2\Model\Event\Event;
use OAuth2\Model\RefreshToken\RefreshToken;

final class RefreshTokenCreatedEvent extends Event
{
    /**
     * @var RefreshToken
     */
    private $refreshToken;

    /**
     * RefreshTokenCreatedEvent constructor.
     *
     * @param RefreshToken $refreshToken
     */
    protected function __construct(RefreshToken $refreshToken)
    {
        parent::__construct();
        $this->refreshToken = $refreshToken;
    }

    /**
     * @param RefreshToken $refreshToken
     *
     * @return self
     */
    public static function create(RefreshToken $refreshToken): self
    {
        return new self($refreshToken);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): \JsonSerializable
    {
        return $this->refreshToken;
    }
}
