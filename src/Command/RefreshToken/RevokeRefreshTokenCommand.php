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

namespace OAuth2\Command\RefreshToken;

use OAuth2\Model\RefreshToken\RefreshToken;

final class RevokeRefreshTokenCommand
{
    /**
     * @var RefreshToken
     */
    private $refreshToken;

    /**
     * RevokeRefreshTokenCommand constructor.
     *
     * @param RefreshToken $refreshToken
     */
    protected function __construct(RefreshToken $refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }

    /**
     * @param RefreshToken $refreshToken
     *
     * @return RevokeRefreshTokenCommand
     */
    public static function create(RefreshToken $refreshToken): self
    {
        return new self($refreshToken);
    }

    /**
     * @return RefreshToken
     */
    public function getRefreshToken(): RefreshToken
    {
        return $this->refreshToken;
    }
}
