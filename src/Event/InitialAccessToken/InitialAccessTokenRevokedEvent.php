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

namespace OAuth2\Event\InitialAccessToken;

use OAuth2\Model\Event\Event;
use OAuth2\Model\InitialAccessToken\InitialAccessToken;

final class InitialAccessTokenRevokedEvent extends Event
{
    /**
     * @var InitialAccessToken
     */
    private $initialAccessToken;

    /**
     * InitialAccessTokenRevokedEvent constructor.
     *
     * @param InitialAccessToken $initialAccessToken
     */
    protected function __construct(InitialAccessToken $initialAccessToken)
    {
        parent::__construct();
        $this->initialAccessToken = $initialAccessToken;
    }

    /**
     * @param InitialAccessToken $initialAccessToken
     *
     * @return self
     */
    public static function create(InitialAccessToken $initialAccessToken): self
    {
        return new self($initialAccessToken);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): \JsonSerializable
    {
        return $this->initialAccessToken;
    }
}
