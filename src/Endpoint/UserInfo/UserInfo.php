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

namespace OAuth2\Endpoint\UserInfo;

use Assert\Assertion;
use OAuth2\Endpoint\UserInfo\ScopeSupport\UserInfoScopeSupportManager;
use OAuth2\Endpoint\UserInfo\ClaimSource\ClaimSourceManager;
use OAuth2\Model\Client\Client;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\OpenIdConnect\Pairwise\PairwiseSubjectIdentifierAlgorithmInterface;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use Psr\Http\Message\UriInterface;

final class UserInfo
{
    /**
     * @var null|PairwiseSubjectIdentifierAlgorithmInterface
     */
    private $pairwiseAlgorithm = null;

    /**
     * @var bool
     */
    private $isPairwiseSubjectDefault = false;

    /**
     * @var UserInfoScopeSupportManager
     */
    private $userinfoScopeSupportManager;

    /**
     * @var ClaimSourceManager
     */
    private $claimSourceManager;

    /**
     * UserInfo constructor.
     *
     * @param UserInfoScopeSupportManager $userinfoScopeSupportManager
     * @param ClaimSourceManager          $claimSourceManager
     */
    public function __construct(UserInfoScopeSupportManager $userinfoScopeSupportManager, ClaimSourceManager $claimSourceManager)
    {
        $this->userinfoScopeSupportManager = $userinfoScopeSupportManager;
        $this->claimSourceManager = $claimSourceManager;
    }

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
    public function getUserinfo(Client $client, UserAccount $userAccount, UriInterface $redirectUri, $claimsLocales, array $requestClaims, array $scope): array
    {
        $this->checkScope($scope);
        $requestClaims = array_merge(
            $this->getClaimsFromClaimScope($scope),
            $requestClaims
        );
        $requestClaims['sub'] = null;
        $claims = $this->getClaimValues($userAccount, $claimsLocales, $requestClaims);
        $claims = array_merge(
            $claims,
            $this->claimSourceManager->getUserInfo($userAccount, $scope, [])
        );
        $claims['sub'] = $this->calculateSubjectIdentifier($client, $userAccount, $redirectUri);

        return $claims;
    }

    /**
     * @param string[] $scopes
     *
     * @return array
     */
    private function getClaimsFromClaimScope(array $scopes): array
    {
        $result = [];
        foreach ($scopes as $scope) {
            if ($this->userinfoScopeSupportManager->has($scope)) {
                $scope_claims = $this->userinfoScopeSupportManager->get($scope)->getClaims();
                foreach ($scope_claims as $scope_claim) {
                    $result[$scope_claim] = null;
                }
            }
        }

        return $result;
    }

    /**
     * @param UserAccount $userAccount
     * @param array|null  $claimsLocales
     * @param array       $claims
     *
     * @return array
     */
    private function getClaimValues(UserAccount $userAccount, $claimsLocales, array $claims): array
    {
        $result = [];
        if (null === $claimsLocales) {
            $claimsLocales = [];
        } elseif (true === is_string($claimsLocales)) {
            $claimsLocales = explode(' ', $claimsLocales);
        }
        $claimsLocales[] = '';
        foreach ($claims as $claim => $config) {
            foreach ($claimsLocales as $claims_locale) {
                $claim_locale = $this->computeClaimWithLocale($claim, $claims_locale);
                $claim_value = $this->getUserClaim($userAccount, $claim_locale, $config);
                if (null !== $claim_value) {
                    $result[$claim_locale] = $claim_value;
                    break;
                }
            }
        }

        return $result;
    }

    /**
     * @param string $claim
     * @param string $locale
     *
     * @return string
     */
    protected function computeClaimWithLocale($claim, $locale): string
    {
        if (empty($locale)) {
            return $claim;
        }

        return sprintf('%s#%s', $claim, $locale);
    }

    /**
     * @param UserAccount $userAccount
     * @param string      $claim
     * @param string      $claim
     * @param null|array  $config
     *
     * @return null|mixed
     */
    protected function getUserClaim(UserAccount $userAccount, $claim, $config)
    {
        //The parameter $config is not yet used and the claim is returned as-is whatever the client requested
        //To be fixed
        if ($userAccount->has($claim)) {
            return $userAccount->get($claim);
        }
    }

    /**
     * @param string[] $scope
     *
     * @throws OAuth2Exception
     */
    private function checkScope($scope)
    {
        if (!in_array('openid', $scope)) {
            throw new OAuth2Exception(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'Access token does not contain the \'openid\' scope.']);
        }
    }

    /**
     * @param PairwiseSubjectIdentifierAlgorithmInterface $pairwiseAlgorithm
     */
    public function enablePairwiseSubject(PairwiseSubjectIdentifierAlgorithmInterface $pairwiseAlgorithm)
    {
        $this->pairwiseAlgorithm = $pairwiseAlgorithm;
    }

    public function setPairwiseSubjectByDefault()
    {
        Assertion::notNull($this->pairwiseAlgorithm, 'The pairwise algorithm must be set before calling this method.');
        $this->isPairwiseSubjectDefault = true;
    }

    public function setPublicSubjectByDefault()
    {
        $this->isPairwiseSubjectDefault = false;
    }

    /**
     * @return bool
     */
    public function isPairwiseSubjectIdentifierSupported(): bool
    {
        return null !== $this->pairwiseAlgorithm;
    }

    /**
     * @return PairwiseSubjectIdentifierAlgorithmInterface|null
     */
    public function getPairwiseSubjectIdentifierAlgorithm()
    {
        return $this->pairwiseAlgorithm;
    }

    /**
     * @return bool
     */
    public function isPairwiseSubjectDefault(): bool
    {
        return $this->isPairwiseSubjectDefault;
    }

    /**
     * @param Client       $client
     * @param UserAccount  $userAccount
     * @param UriInterface $redirectUri
     *
     * @return string
     */
    protected function calculateSubjectIdentifier(Client $client, UserAccount $userAccount, UriInterface $redirectUri): string
    {
        $sub = $userAccount->getId()->getValue();

        if (false === $this->isPairwiseSubjectIdentifierSupported()) {
            return $sub;
        }
        if ($client->has('subject_type') && ('pairwise' === $client->get('subject_type') || true === $this->isPairwiseSubjectDefault())) {
            $sectorIdentifierHost = $this->getSectorIdentifierHost($client, $redirectUri);

            return $this->pairwiseAlgorithm->calculateSubjectIdentifier(
                $userAccount,
                $sectorIdentifierHost
            );
        }

        return $sub;
    }

    /**
     * @param Client       $client
     * @param UriInterface $redirectUri
     *
     * @return string
     */
    private function getSectorIdentifierHost(Client $client, UriInterface $redirectUri): string
    {
        $uri = $redirectUri;

        if (true === $client->has('sector_identifier_uri')) {
            $uri = $client->get('sector_identifier_uri');
        }

        $data = parse_url($uri);
        Assertion::true(is_array($data) && array_key_exists('host', $data), sprintf('Invalid Sector Identifier Uri \'%s\'.', $uri));

        return $data['host'];
    }
}
