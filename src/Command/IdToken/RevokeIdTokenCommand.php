<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Command\IdToken;

use OAuth2\Model\IdToken\IdToken;

final class RevokeIdTokenCommand
{
    /**
     * @var IdToken
     */
    private $idToken;

    /**
     * RevokeIdTokenCommand constructor.
     *
     * @param IdToken $idToken
     */
    protected function __construct(IdToken $idToken)
    {
        $this->idToken = $idToken;
    }

    /**
     * @param IdToken $idToken
     *
     * @return RevokeIdTokenCommand
     */
    public static function create(IdToken $idToken): self
    {
        return new self($idToken);
    }

    /**
     * @return IdToken
     */
    public function getIdToken(): IdToken
    {
        return $this->idToken;
    }
}
