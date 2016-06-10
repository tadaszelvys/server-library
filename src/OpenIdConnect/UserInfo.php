<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\OpenIdConnect;

use Assert\Assertion;
use OAuth2\Behaviour\HasExceptionManager;
use OAuth2\Client\ClientInterface;
use OAuth2\Exception\ExceptionManagerInterface;
use OAuth2\OpenIdConnect\ClaimSource\ClaimSourceManagerInterface;
use OAuth2\OpenIdConnect\UserinfoScopeSupport\UserinfoScopeSupportInterface;
use OAuth2\User\UserInterface;

final class UserInfo implements UserInfoInterface
{
    use HasExceptionManager;
    use HasPairwiseSubjectIdentifierSupportTrait;

    /**
     * @var \OAuth2\OpenIdConnect\UserinfoScopeSupport\UserinfoScopeSupportInterface[]
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
     * @param \OAuth2\OpenIdConnect\UserinfoScopeSupport\UserinfoScopeSupportInterface $userinfo_scope_support
     */
    public function addUserInfoScopeSupport(UserinfoScopeSupportInterface $userinfo_scope_support)
    {
        $scope = $userinfo_scope_support->getScope();
        Assertion::false(array_key_exists($scope, $this->userinfo_scope_supports), sprintf('The userinfo scope "%s" is already supported.', $scope));
        $this->userinfo_scope_supports[] = $userinfo_scope_support;
    }

    /**
     * {@inheritdoc}
     */
    public function getUserinfo(ClientInterface $client, UserInterface $user, $redirect_uri, array $request_claims, array $scope)
    {
        $this->checkScope($scope);
        $request_claims = array_merge(
            $this->getClaimsFromClaimScope($scope),
            $request_claims
        );
        $request_claims['sub'] = null;
        $claims = $this->getClaimValues($user, $request_claims);
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
     * @param array                      $claims
     *
     * @return array
     */
    private function getClaimValues(UserInterface $user, array $claims)
    {
        $result = [];
        foreach ($claims as $claim => $config) {
            $claim_value = $this->getUserClaim($user, $claim, $config);
            if (null !== $claim_value) {
                $result[$claim] = $claim_value;
            }
        }

        return $result;
    }

    /**
     * @param \OAuth2\User\UserInterface $user
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
     * @param null|array $config
     *
     * @return bool
     */
    private function isClaimEssential($config)
    {
        if (null === $config || !is_array($config)) {
            return false;
        }
        if (array_key_exists('essential', $config) && is_bool($config['essential'])) {
            return $config['essential'];
        }

        // We ignore the configuration if not correctly defined (no error is thrown as required by the specification
        return false;
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
     * @return \OAuth2\OpenIdConnect\UserinfoScopeSupport\UserinfoScopeSupportInterface[]
     */
    private function getSupportedUserInfoScopes()
    {
        return $this->userinfo_scope_supports;
    }
}
