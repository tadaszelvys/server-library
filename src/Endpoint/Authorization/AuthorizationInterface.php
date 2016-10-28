<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace OAuth2\Endpoint\Authorization;

use OAuth2\UserAccount\UserAccountInterface;

interface AuthorizationInterface
{
    /**
     * @param \OAuth2\UserAccount\UserAccountInterface $user_account
     */
    public function setUserAccount(UserAccountInterface $user_account);

    /**
     * @return \OAuth2\UserAccount\UserAccountInterface
     */
    public function getUserAccount();

    /**
     * @return \OAuth2\Client\ClientInterface
     */
    public function getClient();

    /**
     * @return array
     */
    public function getQueryParams();

    /**
     * @return array
     */
    public function getPrompt();

    /**
     * @param string $prompt
     *
     * @return bool
     */
    public function hasPrompt($prompt);

    /**
     * @param array $scope
     */
    public function setScopes(array $scope);

    /**
     * @return array
     */
    public function getScopes();

    /**
     * @param string $scope
     *
     * @return bool
     */
    public function hasScope($scope);

    /**
     * @param string $scope
     */
    public function removeScope($scope);

    /**
     * @param string $scope
     */
    public function addScope($scope);

    /**
     * @return bool
     */
    public function isAuthorized();

    /**
     * @param bool $is_authorized
     */
    public function setAuthorized($is_authorized);

    /**
     * @param string $param
     *
     * @return bool
     */
    public function hasQueryParam($param);

    /**
     * @param string $param
     *
     * @return mixed
     */
    public function getQueryParam($param);

    /**
     * @param string $key
     *
     * @return bool
     */
    public function hasData($key);

    /**
     * @param string $key
     *
     * @return mixed
     */
    public function getData($key);

    /**
     * @param string $key
     * @param mixed  $data
     *
     * @return mixed
     */
    public function setData($key, $data);

    /**
     * @return \OAuth2\Grant\ResponseTypeInterface[]
     */
    public function getResponseTypes();

    /**
     * @return \OAuth2\ResponseMode\ResponseModeInterface
     */
    public function getResponseMode();

    /**
     * @return string
     */
    public function getRedirectUri();
}
