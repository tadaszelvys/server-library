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

namespace OAuth2\Event\InitialAccessTokenId;

use OAuth2\Model\Event\Event;
use OAuth2\Model\InitialAccessToken\InitialAccessTokenId;

final class InitialAccessTokenRevokedEvent extends Event
{
    /**
     * @var InitialAccessTokenId
     */
    private $initialAccessTokenId;

    /**
     * InitialAccessTokenRevokedEvent constructor.
     *
     * @param InitialAccessTokenId $initialAccessTokenId
     */
    protected function __construct(InitialAccessTokenId $initialAccessTokenId)
    {
        parent::__construct();
        $this->initialAccessTokenId = $initialAccessTokenId;
    }

    /**
     * @param InitialAccessTokenId $initialAccessTokenId
     *
     * @return self
     */
    public static function create(InitialAccessTokenId $initialAccessTokenId): self
    {
        return new self($initialAccessTokenId);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'initial_access_token_id' => $this->initialAccessTokenId,
        ];
    }
}
