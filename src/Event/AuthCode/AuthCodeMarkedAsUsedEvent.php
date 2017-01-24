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

namespace OAuth2\Event\AuthCode;

use OAuth2\Model\AuthCode\AuthCodeId;
use OAuth2\Model\Event\Event;

final class AuthCodeMarkedAsUsedEvent extends Event
{
    /**
     * @var AuthCodeId
     */
    private $authCodeId;

    /**
     * @var \DateTimeImmutable
     */
    private $usedAt;

    /**
     * AuthCodeMarkedAsUsedEvent constructor.
     *
     * @param AuthCodeId         $authCodeId
     * @param \DateTimeImmutable $usedAt
     */
    protected function __construct(AuthCodeId $authCodeId, \DateTimeImmutable $usedAt)
    {
        parent::__construct();
        $this->authCodeId = $authCodeId;
        $this->usedAt = $usedAt;
    }

    /**
     * @param AuthCodeId         $authCodeId
     * @param \DateTimeImmutable $usedAt
     *
     * @return self
     */
    public static function create(AuthCodeId $authCodeId, \DateTimeImmutable $usedAt): self
    {
        return new self($authCodeId, $usedAt);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'auth_code_id' => $this->authCodeId,
            'used_at'      => $this->usedAt->getTimestamp(),
        ];
    }
}
