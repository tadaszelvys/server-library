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

namespace OAuth2\Model\ClaimSource;

use OAuth2\Model\UserAccount\UserAccount;

class ClaimSourceManager implements ClaimSourceManagerInterface
{
    /**
     * @var ClaimSourceInterface[]
     */
    private $claim_sources = [];

    /**
     * @param ClaimSourceInterface $claim_source
     */
    public function addClaimSource(ClaimSourceInterface $claim_source)
    {
        $this->claim_sources[] = $claim_source;
    }

    /**
     * @return ClaimSourceInterface[]
     */
    public function getClaimSources()
    {
        return $this->claim_sources;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserInfo(UserAccount $userAccount, array $scope, array $claims)
    {
        $claims = [
            '_claim_names'   => [],
            '_claim_sources' => [],
        ];
        $i = 0;

        foreach ($this->getClaimSources() as $claim_source) {
            $result = $claim_source->getUserInfo($userAccount, $scope, $claims);
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
