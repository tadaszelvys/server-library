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

use OAuth2\Model\UserAccount\UserAccount;
use Psr\Http\Message\UriInterface;

interface PairwiseSubjectIdentifierAlgorithmInterface
{
    /**
     * @param UserAccount  $user
     * @param UriInterface $sectorIdentifierUri
     *
     * @return string
     */
    public function calculateSubjectIdentifier(UserAccount $user, UriInterface $sectorIdentifierUri): string;

    /**
     * @param string $subjectIdentifier
     *
     * @return string|null
     */
    public function getPublicIdFromSubjectIdentifier(string $subjectIdentifier);
}
