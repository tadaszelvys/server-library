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

use Assert\Assertion;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\OpenIdConnect\ClaimSource\ClaimSourceManagerInterface;
use OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportInterface;
use OAuth2\User\UserInterface;

final class UserInfo implements UserInfoInterface
{
    use HasExceptionManager;
    use HasPairwiseSubjectIdentifierSupportTrait;

    /**
     * @var \OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserInfoScopeSupportInterface[]
     */
    private $userinfo_scope_supports = [];

    private $claim_source_manager;

    /**
     * UserInfo constructor.
     *
     * @param \OAuth2\OpenIdConnect\ClaimSource\ClaimSourceManagerInterface $claim_source_manager
     * @param \OAuth2\Exception\ExceptionManagerInterface                   $exception_manager
     */
    public function __construct(ClaimSourceManagerInterface $claim_source_manager, ExceptionManagerInterface $exception_manager)
    {
        $this->setExceptionManager($exception_manager);
        $this->claim_source_manager = $claim_source_manager;
    }

    /**
     * @param \OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserinfoScopeSupportInterface $userinfo_scope_support
     */
    public function addUserInfoScopeSupport(UserInfoScopeSupportInterface $userinfo_scope_support)
    {
        $scope = $userinfo_scope_support->getScope();
        Assertion::false(array_key_exists($scope, $this->userinfo_scope_supports), sprintf('The userinfo scope "%s" is already supported.', $scope));
        $this->userinfo_scope_supports[] = $userinfo_scope_support;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserinfo(ClientInterface $client, UserInterface $user, $redirect_uri, $claims_locales, array $request_claims, array $scope)
    {
        $this->checkScope($scope);
        $request_claims = array_merge(
            $this->getClaimsFromClaimScope($scope),
            $request_claims
        );
        $request_claims['sub'] = null;
        $claims = $this->getClaimValues($user, $claims_locales, $request_claims);
        $claims = array_merge(
            $claims,
            $this->claim_source_manager->getUserInfo($user, $scope, [])
        );
        $claims['sub'] = $this->calculateSubjectIdentifier($client, $user, $redirect_uri);

        return $claims;
    }

    /**
     * @param string[] $scope
     *
     * @return array
     */
    private function getClaimsFromClaimScope(array $scope)
    {
        $result = [];
        foreach ($this->getSupportedUserInfoScopes() as $supported_userinfo_scope) {
            if (in_array($supported_userinfo_scope->getScope(), $scope)) {
                $scope_claims = $supported_userinfo_scope->getClaims();
                foreach ($scope_claims as $scope_claim) {
                    $result[$scope_claim] = null;
                }
            }
        }

        return $result;
    }

    /**
     * @param \OAuth2\User\UserInterface $user
     * @param array|null                 $claims_locales
     * @param array                      $claims
     *
     * @return array
     */
    private function getClaimValues(UserInterface $user, $claims_locales, array $claims)
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
                $claim_value = $this->getUserClaim($user, $claim_locale, $config);
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
     * @param \OAuth2\User\UserInterface $user
     * @param string                     $claim
     * @param string                     $claim
     * @param null|array                 $config
     *
     * @return null|mixed
     */
    protected function getUserClaim(UserInterface $user, $claim, $config)
    {
        if ($user->has($claim)) {
            return $user->get($claim);
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
            throw $this->getExceptionManager()->getBadRequestException(
                ExceptionManagerInterface::INVALID_REQUEST,
                'Access token does not contain the "openid" scope.'
            );
        }
    }

    /**
     * @return \OAuth2\OpenIdConnect\UserInfo\ScopeSupport\UserinfoScopeSupportInterface[]
     */
    private function getSupportedUserInfoScopes()
    {
        return $this->userinfo_scope_supports;
    }
}
