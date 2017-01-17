<?php declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\AuthCode;

use OAuth2\Model\AuthCode\AuthCode;

final class RevokeAuthCodeCommand
{
    /**
     * @var AuthCode
     */
    private $authCode;

    /**
     * RevokeAuthCodeCommand constructor.
     *
     * @param AuthCode $authCode
     */
    protected function __construct(AuthCode $authCode)
    {
        $this->authCode = $authCode;
    }

    /**
     * @param AuthCode $authCode
     *
     * @return RevokeAuthCodeCommand
     */
    public static function create(AuthCode $authCode): self
    {
        return new self($authCode);
    }

    /**
     * @return AuthCode
     */
    public function getAuthCode(): AuthCode
    {
        return $this->authCode;
    }
}
