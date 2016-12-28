<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
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
     * @param array $json
     *
     * @return \JsonSerializable
     */
    protected static function createPayloadFromJson(array $json): \JsonSerializable
    {
        return InitialAccessToken::createFromJson($json);
    }

    /**
     * @param InitialAccessToken $initialAccessToken
     *
     * @return self
     */
    public static function create(InitialAccessToken $initialAccessToken): self
    {
        $event = new self($initialAccessToken);

        return $event;
    }

    /**
     * {@inheritdoc}
     */
    public function jsonSerialize(): array
    {
        return [
            'id'          => $this->getEventId()->getValue(),
            'type'        => self::class,
            'recorded_on' => (float) $this->getRecordedOn()->format('U.u'),
            'payload'     => $this->getPayload()->jsonSerialize(),
        ];
    }
}
