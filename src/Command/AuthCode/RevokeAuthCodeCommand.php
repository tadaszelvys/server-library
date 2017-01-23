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

namespace OAuth2\Command\AuthCode;

use OAuth2\Model\AuthCode\AuthCodeId;

final class RevokeAuthCodeCommand
{
    /**
     * @var AuthCodeId
     */
    private $authCodeId;

    /**
     * RevokeAuthCodeCommand constructor.
     *
     * @param AuthCodeId $authCodeId
     */
    protected function __construct(AuthCodeId $authCodeId)
    {
        $this->authCodeId = $authCodeId;
    }

    /**
     * @param AuthCodeId $authCodeId
     *
     * @return RevokeAuthCodeCommand
     */
    public static function create(AuthCodeId $authCodeId): self
    {
        return new self($authCodeId);
    }

    /**
     * @return AuthCodeId
     */
    public function getAuthCodeId(): AuthCodeId
    {
        return $this->authCodeId;
    }
}
