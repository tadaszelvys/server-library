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

final class RefreshTokenRevokedEvent extends Event
{
    /**
     * @param array $json
     *
     * @return \JsonSerializable
     */
    protected static function createPayloadFromJson(array $json): \JsonSerializable
    {
        return RefreshToken::createFromJson($json);
    }

    /**
     * @param RefreshToken $refreshToken
     *
     * @return self
     */
    public static function create(RefreshToken $refreshToken): self
    {
        $event = new self($refreshToken);

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
