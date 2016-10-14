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

use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\OpenIdConnect\ClaimSource\ClaimSourceManagerInterface;
use OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportManagerInterface;
use OAuth2\UserAccount\UserAccountInterface;

final class UserInfo implements UserInfoInterface
{
    use HasExceptionManager;
    use HasPairwiseSubjectIdentifierSupport;
    use HasUserInfoScopeSupportManager;

    private $claim_source_manager;

    /**
     * UserInfo constructor.
     *
     * @param \OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportManagerInterface $userinfo_scope_support_manager
     * @param \OAuth2\OpenIdConnect\ClaimSource\ClaimSourceManagerInterface                    $claim_source_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                                      $exception_manager
     */
    public function __construct(UserInfoScopeSupportManagerInterface $userinfo_scope_support_manager, ClaimSourceManagerInterface $claim_source_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->setUserInfoScopeSupportManager($userinfo_scope_support_manager);
        $this->setExceptionManager($exception_manager);
        $this->claim_source_manager = $claim_source_manager;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserinfo(ClientInterface $client, UserAccountInterface $user_account, $redirect_uri, $claims_locales, array $request_claims, array $scope)
    {
        $this->checkScope($scope);
        $request_claims = array_merge(
            $this->getClaimsFromClaimScope($scope),
            $request_claims
        );
        $request_claims['sub'] = null;
        $claims = $this->getClaimValues($user_account, $claims_locales, $request_claims);
        $claims = array_merge(
            $claims,
            $this->claim_source_manager->getUserInfo($user_account, $scope, [])
        );
        $claims['sub'] = $this->calculateSubjectIdentifier($client, $user_account, $redirect_uri);

        return $claims;
    }

    /**
     * @param string[] $scopes
     *
     * @return array
     */
    private function getClaimsFromClaimScope(array $scopes)
    {
        $result = [];
        foreach ($scopes as $scope) {
            if ($this->getUserInfoScopeSupportManager()->hasUserInfoScopeSupport($scope)) {
                $scope_claims = $this->getUserInfoScopeSupportManager()->getUserInfoScopeSupport($scope)->getClaims();
                foreach ($scope_claims as $scope_claim) {
                    $result[$scope_claim] = null;
                }
            }
        }

        return $result;
    }

    /**
     * @param \OAuth2\UserAccount\UserAccountInterface $user_account
     * @param array|null                               $claims_locales
     * @param array                                    $claims
     *
     * @return array
     */
    private function getClaimValues(UserAccountInterface $user_account, $claims_locales, array $claims)
    {
        $result = [];
        if (null === $claims_locales) {
            $claims_locales = [];
        } elseif (true === is_string($claims_locales)) {
            $claims_locales = explode(' ', $claims_locales);
        }
        $claims_locales[] = '';
        foreach ($claims as $claim => $config) {
            foreach ($claims_locales as $claims_locale) {
                $claim_locale = $this->computeClaimWithLocale($claim, $claims_locale);
                $claim_value = $this->getUserClaim($user_account, $claim_locale, $config);
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
    protected function computeClaimWithLocale($claim, $locale)
    {
        if (empty($locale)) {
            return $claim;
        }

        return sprintf('%s#%s', $claim, $locale);
    }

    /**
     * @param \OAuth2\UserAccount\UserAccountInterface $user_account
     * @param string                                   $claim
     * @param string                                   $claim
     * @param null|array                               $config
     *
     * @return null|mixed
     */
    protected function getUserClaim(UserAccountInterface $user_account, $claim, $config)
    {
        //The parameter $config is not yet used and the claim is returned as-is whatever the client requested
        //To be fixed
        if ($user_account->has($claim)) {
            return $user_account->get($claim);
        }
    }

    /**
     * @param string[] $scope
     *
     * @throws \OAuth2\Exception\BadRequestExceptionInterface
     */
    private function checkScope($scope)
    {
        if (!in_array('openid', $scope)) {
            throw $this->getExceptionManager()->getBadRequestException(ExceptionManagerInterface::INVALID_REQUEST, 'Access token does not contain the "openid" scope.');
        }
    }
}
