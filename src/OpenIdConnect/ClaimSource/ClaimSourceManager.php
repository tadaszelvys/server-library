<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect\ClaimSource;

use OAuth2\UserAccount\UserAccountInterface;

class ClaimSourceManager implements ClaimSourceManagerInterface
{
    /**
     * @var \OAuth2\OpenIdConnect\ClaimSource\ClaimSourceInterface[]
     */
    private $claim_sources = [];

    /**
     * @param \OAuth2\OpenIdConnect\ClaimSource\ClaimSourceInterface $claim_source
     */
    public function addClaimSource(ClaimSourceInterface $claim_source)
    {
        $this->claim_sources[] = $claim_source;
    }

    /**
     * @return \OAuth2\OpenIdConnect\ClaimSource\ClaimSourceInterface[]
     */
    public function getClaimSources()
    {
        return $this->claim_sources;
    }

    /**
     * @param \OAuth2\UserAccount\UserAccountInterface $user_account
     * @param string[]                                 $scope
     * @param array                                    $claims
     *
     * @return array
     */
    public function getUserInfo(UserAccountInterface $user_account, array $scope, array $claims)
    {
        $claims = [
            '_claim_names'   => [],
            '_claim_sources' => [],
        ];
        $i = 0;

        foreach ($this->getClaimSources() as $claim_source) {
            $result = $claim_source->getUserInfo($user_account, $scope, $claims);
            if (null !== $result) {
                $i++;
                $src = sprintf('src%d', $i);
                $_claim_names = [];
                foreach ($result->getAvailableClaims() as $claim) {
                    if ('sub' !== $claim) {
                        $_claim_names[$claim] = $src;
                    }
                }
                $claims['_claim_names'] = array_merge(
                    $claims['_claim_names'],
                    $_claim_names
                );
                $claims['_claim_sources'][$src] = $result->getSource();
            }
        }

        return empty($claims['_claim_names']) ? [] : $claims;
    }
}
