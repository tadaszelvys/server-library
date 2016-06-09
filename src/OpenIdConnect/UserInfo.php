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
    public function getUserinfo(ClientInterface $client, UserInterface $user, $redirect_uri, array $scope)
    {
        $this->checkScope($scope);

        $claims = [
            'sub' => $this->calculateSubjectIdentifier($client, $user, $redirect_uri),
        ];
        $supported_userinfo_scopes = $this->getSupportedUserInfoScopes();
        foreach ($supported_userinfo_scopes as $supported_userinfo_scope) {
            if (in_array($supported_userinfo_scope->getScope(), $scope)) {
                $scope_claims = $supported_userinfo_scope->getClaims();
                foreach ($scope_claims as $scope_claim) {
                    if ($user->has($scope_claim)) {
                        $claims[$scope_claim] = $user->get($scope_claim);
                    }
                }
            }
        }

        $claims = array_merge(
            $claims,
            $this->claim_source_manager->getUserInfo($user, $scope, [])
        );

        return $claims;
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
