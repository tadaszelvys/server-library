<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\InitialAccessToken;

use OAuth2\Model\InitialAccessToken\InitialAccessToken;

final class RevokeInitialAccessTokenCommand
{
    /**
     * @var InitialAccessToken
     */
    private $initialAccessToken;

    /**
     * RevokeInitialAccessTokenCommand constructor.
     *
     * @param InitialAccessToken $initialAccessToken
     */
    protected function __construct(InitialAccessToken $initialAccessToken)
    {
        $this->initialAccessToken = $initialAccessToken;
    }

    /**
     * @param InitialAccessToken $initialAccessToken
     *
     * @return RevokeInitialAccessTokenCommand
     */
    public static function create(InitialAccessToken $initialAccessToken): self
    {
        return new self($initialAccessToken);
    }

    /**
     * @return InitialAccessToken
     */
    public function getInitialAccessToken(): InitialAccessToken
    {
        return $this->initialAccessToken;
    }
}
