<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\UserInfo;

use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\OpenIdConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface;

interface UserInfoInterface
{
    /**
     * @param \OAuth2\OpenIdConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface $algorithm
     */
    public function enablePairwiseSubject(PairwiseSubjectIdentifierAlgorithmInterface $algorithm);

    /**
     * @return bool
     */
    public function isPairwiseSubjectIdentifierSupported();

    /**
     * @return \OAuth2\OpenIdConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface|null
     */
    public function getPairwiseSubjectIdentifierAlgorithm();

    /**
     * @param Client      $client
     * @param UserAccount $user_account
     * @param string      $redirect_uri
     * @param null|array  $claims_locales
     * @param array       $request_claims
     * @param string[]    $scope
     *
     * @return array
     */
    public function getUserinfo(Client $client, UserAccount $user_account, $redirect_uri, $claims_locales, array $request_claims, array $scope);
}
