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

use OAuth2\Model\ClaimSource\ClaimSourceManagerInterface;
use OAuth2\Model\UserAccount\UserAccount;
use OAuth2\Response\OAuth2Exception;
use OAuth2\Response\OAuth2ResponseFactoryManagerInterface;
use OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportManagerInterface;

class UserInfo implements UserInfoInterface
{
    use HasPairwiseSubjectIdentifierSupport;

    private $claim_source_manager;

    /**
     * UserInfo constructor.
     *
     * @param UserInfoScopeSupportManagerInterface $userinfo_scope_support_manager
     * @param ClaimSourceManagerInterface                    $claim_source_manager
     * @param OAuth2ResponseFactoryManagerInterface                                      $response_factory_manager
     */
    public function __construct(UserInfoScopeSupportManagerInterface $userinfo_scope_support_manager, ClaimSourceManagerInterface $claim_source_manager, OAuth2ResponseFactoryManagerInterface $response_factory_manager)
    {
        $this->setUserInfoScopeSupportManager($userinfo_scope_support_manager);
        $this->setResponsefactoryManager($response_factory_manager);
        $this->claim_source_manager = $claim_source_manager;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserinfo(ClientInterface $client, UserAccount $user_account, $redirect_uri, $claims_locales, array $request_claims, array $scope)
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
     * @param UserAccount $user_account
     * @param array|null                               $claims_locales
     * @param array                                    $claims
     *
     * @return array
     */
    private function getClaimValues(UserAccount $user_account, $claims_locales, array $claims)
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
     * @param UserAccount $user_account
     * @param string                                   $claim
     * @param string                                   $claim
     * @param null|array                               $config
     *
     * @return null|mixed
     */
    protected function getUserClaim(UserAccount $user_account, $claim, $config)
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
     * @throws \OAuth2\Response\OAuth2Exception
     */
    private function checkScope($scope)
    {
        if (!in_array('openid', $scope)) {
            throw new OAuth2Exception($this->getResponseFactoryManager()->getResponse(400, ['error' => OAuth2ResponseFactoryManagerInterface::ERROR_INVALID_REQUEST, 'error_description' => 'Access token does not contain the \'openid\' scope.']));
        }
    }
}
