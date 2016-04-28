<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\Pairwise;

use OAuth2\User\UserInterface;

interface PairwiseSubjectIdentifierAlgorithmInterface
{
    /**
     * @param \OAuth2\User\UserInterface $user
     * @param string                     $sector_identifier_uri
     *
     * @return string
     */
    public function calculateSubjectIdentifier(UserInterface $user, $sector_identifier_uri);
}
