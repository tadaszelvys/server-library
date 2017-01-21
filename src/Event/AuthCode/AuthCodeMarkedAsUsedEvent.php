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

use OAuth2\Model\AuthCode\AuthCode;
use OAuth2\Model\Event\Event;

final class AuthCodeMarkedAsUsedEvent extends Event
{
    /**
     * @var AuthCode
     */
    private $authCode;

    /**
     * AuthCodeMarkedAsUsedEvent constructor.
     *
     * @param AuthCode $authCode
     */
    protected function __construct(AuthCode $authCode)
    {
        parent::__construct();
        $this->authCode = $authCode;
    }

    /**
     * @param AuthCode $authCode
     *
     * @return self
     */
    public static function create(AuthCode $authCode): self
    {
        return new self($authCode);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): \JsonSerializable
    {
        return $this->authCode;
    }
}
