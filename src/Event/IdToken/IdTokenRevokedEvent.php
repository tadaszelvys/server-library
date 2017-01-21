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

namespace OAuth2\Event\IdToken;

use OAuth2\Model\Event\Event;
use OAuth2\Model\IdToken\IdToken;

final class IdTokenRevokedEvent extends Event
{
    /**
     * @var IdToken
     */
    private $idToken;

    /**
     * IdTokenRevokedEvent constructor.
     *
     * @param IdToken $idToken
     */
    protected function __construct(IdToken $idToken)
    {
        parent::__construct();
        $this->idToken = $idToken;
    }

    /**
     * @param IdToken $idToken
     *
     * @return self
     */
    public static function create(IdToken $idToken): self
    {
        return new self($idToken);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): \JsonSerializable
    {
        return $this->idToken;
    }
}
