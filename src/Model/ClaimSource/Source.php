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

namespace OAuth2\Model\ClaimSource;

class Source implements SourceInterface
{
    /**
     * @var string[]
     */
    private $available_claims = [];

    /**
     * @var array
     */
    private $source = [];

    /**
     * Source constructor.
     *
     * @param string[] $available_claims
     * @param array    $source
     */
    public function __construct(array $available_claims, array $source)
    {
        $this->available_claims = $available_claims;
        $this->source = $source;
    }

    /**
     * @return string[]
     */
    public function getAvailableClaims()
    {
        return $this->available_claims;
    }

    /**
     * @return array
     */
    public function getSource()
    {
        return $this->source;
    }
}
