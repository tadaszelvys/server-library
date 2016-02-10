<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Test\Stub;

use Jose\ClaimChecker\AudienceChecker;
use Jose\ClaimChecker\ClaimCheckerManager as Base;

class ClaimCheckerManager extends Base
{
    /**
     * @var string
     */
    private $audience;

    /**
     * ClaimCheckerManager constructor.
     *
     * @param string $audience
     */
    public function __construct($audience)
    {
        $this->audience = $audience;
    }

    /**
     * {@inheritdoc}
     */
    protected function getSupportedClaimCheckers()
    {
        return array_merge(
            parent::getSupportedClaimCheckers(),
            [
                new AudienceChecker($this->audience),
            ]
        );
    }
}
