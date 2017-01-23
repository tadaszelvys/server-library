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
use OAuth2\Model\RefreshToken\RefreshTokenId;

final class RefreshTokenRevokedEvent extends Event
{
    /**
     * @var RefreshToken
     */
    private $refreshTokenId;

    /**
     * RefreshTokenRevokedEvent constructor.
     *
     * @param RefreshTokenId $refreshTokenId
     */
    protected function __construct(RefreshTokenId $refreshTokenId)
    {
        parent::__construct();
        $this->refreshTokenId = $refreshTokenId;
    }

    /**
     * @param RefreshTokenId $refreshTokenId
     *
     * @return self
     */
    public static function create(RefreshTokenId $refreshTokenId): self
    {
        return new self($refreshTokenId);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'refresh_token_id' => $this->refreshTokenId,
        ];
    }
}
