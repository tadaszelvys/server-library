<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\UserInfo;

use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\OpenIdConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface;
use Psr\Http\Message\UriInterface;

interface UserInfoInterface
{
    /**
     * @param PairwiseSubjectIdentifierAlgorithmInterface $algorithm
     */
    public function enablePairwiseSubject(PairwiseSubjectIdentifierAlgorithmInterface $algorithm);

    /**
     * @return bool
     */
    public function isPairwiseSubjectIdentifierSupported(): bool;

    /**
     * @return PairwiseSubjectIdentifierAlgorithmInterface|null
     */
    public function getPairwiseSubjectIdentifierAlgorithm();

    /**
     * @param Client       $client
     * @param UserAccount  $userAccount
     * @param UriInterface $redirectUri
     * @param null|array   $claimsLocales
     * @param array        $requestClaims
     * @param string[]     $scope
     *
     * @return array
     */
    public function getUserinfo(Client $client, UserAccount $userAccount, UriInterface $redirectUri, $claimsLocales, array $requestClaims, array $scope): array;
}
