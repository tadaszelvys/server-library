<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Event\AuthCode;

use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\Event\Event;

final class AuthCodeRevokedEvent extends Event
{
    /**
     * @param array $json
     *
     * @return \JsonSerializable
     */
    protected static function createPayloadFromJson(array $json): \JsonSerializable
    {
        return AuthCode::createFromJson($json);
    }

    /**
     * @param AuthCode $authCode
     *
     * @return self
     */
    public static function create(AuthCode $authCode): self
    {
        $event = new self($authCode);

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
