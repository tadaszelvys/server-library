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

namespace OAuth2\Event\AuthCodeId;

use OAuth2\Model\AuthCode\AuthCodeId;
use OAuth2\Model\Event\Event;

final class AuthCodeWithoutRefreshTokenEvent extends Event
{
    /**
     * @var AuthCodeId
     */
    private $authCodeId;

    /**
     * AuthCodeCreatedEvent constructor.
     *
     * @param AuthCodeId $authCodeId
     */
    protected function __construct(AuthCodeId $authCodeId)
    {
        parent::__construct();
        $this->authCodeId = $authCodeId;
    }

    /**
     * @param AuthCodeId $authCodeId
     *
     * @return self
     */
    public static function create(AuthCodeId $authCodeId): self
    {
        return new self($authCodeId);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return [
            'auth_code_id' => $this->authCodeId,
        ];
    }
}
